use crate::{
    auto_result, ja3,
    net_proxy::{
        certificate_authority::CertificateAuthority, rewind::Rewind, HttpContext, HttpHandler,
        WebSocketContext, WebSocketHandler,
    },
    HTTP_CLIENT,
};

use futures::{Sink, Stream, StreamExt};

use crate::net_proxy::body::Body;
use crate::net_proxy::RequestOrResponse;
use hyper::{
    body::{Bytes, Incoming},
    header::Entry,
    service::service_fn,
    upgrade::Upgraded,
    Method, Request, Response, StatusCode, Uri,
};
use hyper_util::{
    client::legacy::{connect::Connect, Client},
    rt::{TokioExecutor, TokioIo},
    server,
};

use hyper::header::SEC_WEBSOCKET_EXTENSIONS;
use hyper::http::uri::{Authority, Scheme};
use std::{
    convert::Infallible,
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::Arc,
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite},
    net::TcpStream,
    sync::Mutex,
    task::JoinHandle,
};
use tokio_rustls::{client::TlsStream, TlsAcceptor, TlsConnector};
use tokio_tungstenite::{
    tungstenite::{self, protocol::WebSocketConfig, Message},
    Connector, WebSocketStream,
};
use tokio_util::bytes;
use tracing::{error, info_span, instrument, warn, Instrument, Span};

fn bad_request() -> Response<Body> {
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .body(Body::empty())
        .expect("Failed to build response")
}

fn spawn_with_trace<T: Send + Sync + 'static>(
    fut: impl Future<Output = T> + Send + 'static,
    span: Span,
) -> JoinHandle<T> {
    tokio::spawn(fut.instrument(span))
}

// async fn connect_to_dns(
//     authority: &Authority,
//     ca: Arc<ClientConfig>,
// ) -> io::Result<TlsStream<TcpStream>> {
//     let stream = TcpStream::connect(authority.as_ref()).await?;
//     let connector = TlsConnector::from(ca);
//     let host = authority.host();
//     let server_name = match DnsName::try_from_ascii(host.as_bytes()) {
//         Ok(v) => rustls::ServerName::DnsName(v),
//         Err(_e) => {
//             let ip = match IpAddr::from_str(host) {
//                 Ok(v) => v,
//                 Err(_e) => {
//                     panic!("invalid server name:{authority}")
//                 }
//             };
//             let ip_address = rustls::ServerName::IpAddress(ip);
//             ip_address
//         }
//     };
//     let stream = connector.connect(server_name, stream).await?;
//     Ok(stream)
// }
pub(crate) struct InternalProxy<C, CA, H, W> {
    pub ca: Arc<CA>,
    pub client: Client<C, Body>,
    pub server: server::conn::auto::Builder<TokioExecutor>,
    pub http_handler: H,
    pub websocket_handler: W,
    pub websocket_connector: Option<Connector>,
    pub client_addr: SocketAddr,
    pub uri: Uri,
}

impl<C, CA, H, W> Clone for InternalProxy<C, CA, H, W>
where
    C: Clone,
    H: Clone,
    W: Clone,
{
    fn clone(&self) -> Self {
        InternalProxy {
            ca: Arc::clone(&self.ca),
            client: self.client.clone(),
            server: self.server.clone(),
            http_handler: self.http_handler.clone(),
            websocket_handler: self.websocket_handler.clone(),
            websocket_connector: self.websocket_connector.clone(),
            client_addr: self.client_addr,
            uri: self.uri.clone(),
        }
    }
}

impl<C, CA, H, W> InternalProxy<C, CA, H, W>
where
    C: Connect + Clone + Send + Sync + 'static,
    CA: CertificateAuthority,
    H: HttpHandler,
    W: WebSocketHandler,
{
    fn context(&self) -> HttpContext {
        HttpContext {
            client_addr: self.client_addr,
            uri: self.uri.clone(),
        }
    }

    #[instrument(
        skip_all,
        fields(
            version = ?req.version(),
            method = %req.method(),
            uri=%req.uri(),
            client_addr = %self.client_addr,
        )
    )]
    pub(crate) async fn proxy(
        mut self,
        req: Request<Incoming>,
    ) -> Result<Response<Body>, Infallible> {
        let ctx = self.context();

        let req = match self
            .http_handler
            .handle_request(&ctx, req.map(Body::from))
            .instrument(info_span!("handle_request"))
            .await
        {
            RequestOrResponse::Request(req) => req,
            RequestOrResponse::Response(res) => return Ok(res),
        };

        if req.method() == Method::CONNECT {
            Ok(self.process_connect(req))
        } else if hyper_tungstenite::is_upgrade_request(&req) {
            Ok(self.upgrade_websocket(req))
        } else {
            let res = self
                .client
                .request(normalize_request(req))
                .instrument(info_span!("proxy_request"))
                .await;

            match res {
                Ok(res) => Ok(self
                    .http_handler
                    .handle_response(&ctx, res.map(Body::from))
                    .instrument(info_span!("handle_response"))
                    .await),
                Err(err) => Ok(self
                    .http_handler
                    .handle_error(&ctx, err)
                    .instrument(info_span!("handle_error"))
                    .await),
            }
        }
    }

    fn process_connect(mut self, mut req: Request<Body>) -> Response<Body> {
        let authority = match req.uri().authority().cloned() {
            Some(v) => v,
            None => {
                return bad_request();
            }
        };

        let span = info_span!("process_connect");
    
        let fut = async move {
         
            let upgraded = auto_result!(hyper::upgrade::on(&mut req).await ,err=>{
               error!("Upgrade error: {err}");
               return;
            });
            let mut upgraded = TokioIo::new(upgraded);
            let ctx = self.context();
            let uri = &ctx.uri;
            let mut buffer = [0; 4];
            let bytes_read = auto_result!(upgraded.read(&mut buffer).await,e=>{
               error!(
                   "Failed to read from upgraded connection: {e},URI:{uri}"
               );
               return;
            });

            let upgraded = Rewind::new(
                upgraded,
                Bytes::copy_from_slice(buffer[..bytes_read].as_ref()),
            );
            if !self.http_handler.should_intercept(&ctx, &req).await {
                return;
            }
            if buffer == *b"GET " {
                if let Err(e) = self
                    .serve_stream(TokioIo::new(upgraded), Scheme::HTTP, authority)
                    .await
                {
                    error!("WebSocket connect error: {e},URI:{uri}");
                }
                return;
            }

            if buffer[..2] == *b"\x16\x03" {
                let server_config = {
                    let alpn = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
                    let ca = self.ca.clone();
                    let server_config = ca
                        .gen_server_config(&authority, alpn)
                        .instrument(info_span!("gen_server_config"))
                        .await;
                    server_config
                };

                let stream = match TlsAcceptor::from(server_config).accept(upgraded).await {
                    Ok(stream) => TokioIo::new(stream),
                    Err(e) => {
                        error!("Failed to establish TLS connection: {e},URI:{uri}");
                        return;
                    }
                };

                if let Err(e) = self.serve_stream(stream, Scheme::HTTPS, authority).await {
                    if !e.to_string().starts_with("error shutting down connection") {
                        error!("HTTPS connect error: {e},URI:{uri}");
                    }
                }

                return;
            }
            warn!(
                "Unknown protocol, read '{:02X?}' from upgraded connection",
                &buffer[..bytes_read]
            );
        };
        spawn_with_trace(fut, span);
        Response::new(Body::empty())
    }

    #[instrument(skip_all)]
    fn upgrade_websocket(self, req: Request<Body>) -> Response<Body> {
        let mut req = {
            let (mut parts, _) = req.into_parts();

            parts.uri = {
                let mut parts = parts.uri.into_parts();

                parts.scheme = if parts.scheme.unwrap_or(Scheme::HTTP) == Scheme::HTTP {
                    Some("ws".try_into().expect("Failed to convert scheme"))
                } else {
                    Some("wss".try_into().expect("Failed to convert scheme"))
                };

                match Uri::from_parts(parts) {
                    Ok(uri) => uri,
                    Err(_) => {
                        return bad_request();
                    }
                }
            };
            // res.headers_mut().insert(
            //     "Sec-Websocket-Extensions",
            //     HeaderValue::from_str("permessage-deflate; client_max_window_bits=15").unwrap(),
            // );
            parts.headers.remove(SEC_WEBSOCKET_EXTENSIONS);

            Request::from_parts(parts, ())
        };

        match hyper_tungstenite::upgrade(&mut req, None) {
            Ok((res, websocket)) => {
                let span = info_span!("websocket");
                let fut = async move {
                    match websocket.await {
                        Ok(ws) => {
                            if let Err(e) = self.handle_websocket(ws, req).await {
                                error!("Failed to handle WebSocket: {}", e);
                            }
                        }
                        Err(e) => {
                            error!("Failed to upgrade to WebSocket: {}", e);
                        }
                    }
                };

                spawn_with_trace(fut, span);
                res.map(Body::from)
            }
            Err(_) => bad_request(),
        }
    }

    #[instrument(skip_all)]
    async fn handle_websocket(
        self,
        client_socket: WebSocketStream<TokioIo<Upgraded>>,
        req: Request<()>,
    ) -> Result<(), tungstenite::Error> {
        let uri = req.uri().clone();
        let mut cfg = WebSocketConfig::default();
        cfg.accept_unmasked_frames = true;
        let (server_socket, _) = tokio_tungstenite::connect_async_tls_with_config(
            req,
            Some(cfg),
            false,
            self.websocket_connector,
        )
        .await?;

        let (server_sink, server_stream) = server_socket.split();
        let (client_sink, client_stream) = client_socket.split();
        let InternalProxy {
            websocket_handler, ..
        } = self;

        spawn_message_forwarder(
            server_stream,
            client_sink,
            websocket_handler.clone(),
            WebSocketContext::ServerToClient {
                src: uri.clone(),
                dst: self.client_addr,
            },
        );

        spawn_message_forwarder(
            client_stream,
            server_sink,
            websocket_handler,
            WebSocketContext::ClientToServer {
                src: self.client_addr,
                dst: uri,
            },
        );

        Ok(())
    }

    #[instrument(skip_all)]
    async fn serve_stream<I>(
        self,
        stream: I,
        scheme: Scheme,
        authority: Authority,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    where
        I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
    {
        let service = service_fn(|mut req| {
            if req.version() == hyper::Version::HTTP_10 || req.version() == hyper::Version::HTTP_11
            {
                let (mut parts, body) = req.into_parts();

                parts.uri = {
                    let mut parts = parts.uri.into_parts();
                    parts.scheme = Some(scheme.clone());
                    parts.authority = Some(authority.clone());
                    Uri::from_parts(parts).expect("Failed to build URI")
                };

                req = Request::from_parts(parts, body);
            };
            let net_proxy = self.clone();
            async {
                let now = std::time::SystemTime::now();
                let version = req.version();
                let method = req.method().to_string();
                let uri = req.uri().to_string();
                let res = net_proxy.proxy(req).await;
                let end = std::time::SystemTime::now();
                let duration_since = end.duration_since(now).unwrap();
                let secs_f32 = duration_since.as_secs_f32();
                println!(
                    "secs={:.3}s,\tversion={:?},\tmethod={},\turi={uri}",
                    secs_f32, version, method
                );
                res
            }
        });

        self.server
            .serve_connection_with_upgrades(stream, service)
            .await
    }
}

fn spawn_message_forwarder(
    stream: impl Stream<Item = Result<Message, tungstenite::Error>> + Unpin + Send + 'static,
    sink: impl Sink<Message, Error = tungstenite::Error> + Unpin + Send + 'static,
    handler: impl WebSocketHandler,
    ctx: WebSocketContext,
) {
    let span = info_span!("message_forwarder", context = ?ctx);
    let fut = handler.handle_websocket(ctx, stream, sink);
    spawn_with_trace(fut, span);
}

#[instrument(skip_all)]
fn normalize_request<T>(mut req: Request<T>) -> Request<T> {
    // Hyper will automatically add a Host header if needed.
    req.headers_mut().remove(hyper::header::HOST);

    // HTTP/2 supports multiple cookie headers, but HTTP/1.x only supports one.
    if let Entry::Occupied(mut cookies) = req.headers_mut().entry(hyper::header::COOKIE) {
        let joined_cookies = bstr::join(b"; ", cookies.iter());
        cookies.insert(joined_cookies.try_into().expect("Failed to join cookies"));
    }

    *req.version_mut() = hyper::Version::HTTP_11;
    req
}
