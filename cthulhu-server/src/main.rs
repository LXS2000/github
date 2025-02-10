use std::{fs, net::SocketAddr, str::FromStr, sync::Arc};

use async_trait::async_trait;

use hyper::{
    client::HttpConnector, header::HeaderValue, service::Service, Body, Method, Request, Response,
    Uri, Version,
};

use hyper_rustls::HttpsConnector;
use lazy_static::lazy_static;
use local_ip_address::local_ip;

use net_proxy::{
    certificate_authority::RcgenAuthority, Answer, CustomProxy, HttpContext, HttpHandler,
    WebSocketHandler,
};

use serde::Deserialize;

use rustls_pemfile as pemfile;

use time::macros::format_description;
use tracing::Level;
use tracing_subscriber::{fmt::time::LocalTime, FmtSubscriber};

use crate::net_proxy::AddrListenerServer;

mod ja3;
mod net_proxy;
mod proxy;
mod rcgen;
mod utils;

mod macros;

// type NetClient = hyper::Client<HttpsConnector<HttpConnector>, Body>;
type NetClient = reqwest::Client;
type AppProxy<'ca> = CustomProxy<RcgenAuthority, Handler, Handler>;

// const TIME_FMT: &str = "%Y-%m-%d %H:%M:%S";
lazy_static! {



    ///sever http客户端
    pub static ref HTTP_CLIENT: NetClient = {
       let c= reqwest::ClientBuilder::new()
      .tls_built_in_root_certs(true)

    //   .cookie_store(false)
    //   .referer(false)
      .no_brotli().no_deflate().no_gzip()
      .danger_accept_invalid_certs(true)

        .use_rustls_tls().build().unwrap();
    //    let conn=HttpConnector::new();
    //    let conn= hyper_rustls::HttpsConnectorBuilder::new()
    //     .with_native_roots()
    //     .https_or_http().enable_all_versions()
    //     .wrap_connector(conn);
    //    hyper::Client::builder().build(conn)
    c
    };
    pub static ref IS_SYS_PROXY:std::sync::RwLock<bool>=std::sync::RwLock::new(false);

    //CA证书
    pub static ref AUTH:Arc <RcgenAuthority>=Arc::new(read_ca());
    pub static ref CONFIG:Config={
        let bytes = fs::read("./config.json").expect("配置文件读取失败");
        let cfg = serde_json::from_slice::<Config>(&bytes).expect("配置文件格式不正确");
        cfg
    };

}
pub fn reqwest_response_to_hyper(
    res: reqwest::Response,
) -> Result<hyper::Response<Body>, Box<dyn std::error::Error>> {
    let status = res.status();
    let version = res.version();
    let headers = res.headers();
    // println!("{:?}",headers);
    let headers = headers.clone();

    let mut response = hyper::Response::builder()
        .version(version)
        .status(status)
        .body(Body::wrap_stream(res.bytes_stream()))?;
    *response.headers_mut() = headers;
    Ok(response)
}

pub fn reqwest_request_from_hyper(req: hyper::Request<Body>) -> reqwest::Request {
    let (parts, body) = req.into_parts();
    let mut request = reqwest::Request::new(
        parts.method,
        reqwest::Url::from_str(&parts.uri.to_string()).unwrap(),
    );

    *request.headers_mut() = parts.headers;
    *request.version_mut() = parts.version;

    *request.body_mut() = Some(reqwest::Body::from(body));
    request
}
async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install CTRL+C signal handler");

    println!("exit...");
}

#[derive(Debug, Deserialize)]
pub struct Match {
    pub host: String,
    pub ja3: String,
    pub akamai: String,
    pub proxy: Option<String>,
}
#[derive(Debug, Deserialize)]
pub struct Config {
    pub port: u16,
    pub matches: Vec<Match>,
}
#[derive(Debug, Clone)]
struct Handler;
#[async_trait]
impl HttpHandler for Handler {
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        mut req: Request<Body>,
    ) -> Answer<Request<Body>, Response<Body>> {
        if req.method() == Method::CONNECT {
            return Answer::Release(req);
        }
        let uri = req.uri().clone();
        let version = req.version();
        println!("req:{},{:?},{}", req.method(), &version, uri.to_string());

        let headers = req.headers_mut();

        headers.append("mitm-uri", HeaderValue::from_str(&uri.to_string()).unwrap());
        headers.append("mitm-version", HeaderValue::from_str(&format!("{:?}", version)).unwrap());
        let host_ = uri.host().unwrap();
        for Match {
            host,
            ja3,
            akamai,
            proxy,
        } in &CONFIG.matches
        {
            if utils::mini_match(&host, host_) {
                headers.append(
                    "mitm-proxy",
                    HeaderValue::from_str(&proxy.clone().unwrap_or_default()).unwrap(),
                );
                headers.append("mitm-akamai", HeaderValue::from_str(akamai).unwrap());
                headers.append("mitm-ja3", HeaderValue::from_str(ja3).unwrap());
                break;
            }
        }
        *req.uri_mut() = Uri::from_static("https://127.0.0.1:520/");
        let req = reqwest_request_from_hyper(req);
        let call = HTTP_CLIENT.clone().execute(req).await;
        match call {
            Ok(res) => {
                let res = reqwest_response_to_hyper(res).unwrap();
                Answer::Respond(res)
            }
            Err(e) => {
                tracing::error!("{:?} uri:{}", &e, &uri);
                let res = Response::builder()
                    .status(500)
                    .body(Body::from(e.to_string()))
                    .unwrap();
                Answer::Respond(res)
            }
        }
    }
}

#[async_trait]
impl WebSocketHandler for Handler {}

fn read_ca() -> RcgenAuthority {
    let key = utils::read_bytes("./ca/ca.key").expect("读取密钥文件失败!");
    let cert = utils::read_bytes("./ca/ca.cer").expect("读取证书文件失败!");

    let mut private_key_bytes: &[u8] = &key;
    let mut ca_cert_bytes: &[u8] = &cert;

    let private_key = rustls::PrivateKey(
        pemfile::pkcs8_private_keys(&mut private_key_bytes)
            .expect("Failed to parse private key")
            .remove(0),
    );

    let ca_cert = rustls::Certificate(
        pemfile::certs(&mut ca_cert_bytes)
            .expect("Failed to parse CA certificate")
            .remove(0),
    );

    let auth = RcgenAuthority::new(private_key.into(), ca_cert, 1_000)
        .expect("Failed to create Certificate Authority");
    auth
}
async fn run_server() {
    //初始化ca证书
    let port = CONFIG.port;
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    let rustls = tokio_tungstenite::Connector::Rustls(Arc::new(ja3::random_ja3(0)));
    let proxy = AppProxy::new(
        AUTH.clone(),
        AddrListenerServer::Addr(addr),
        Handler,
        Handler,
        Some(rustls),
    );
    let local_ip = auto_result!(local_ip(),err=>{
        panic!("获取本机内网地址失败：{}",err);
    });
    println!("server at port {local_ip}:{port}");
    if let Err(e) = proxy.start(shutdown_signal()).await {
        panic!("{}", e);
    }
}

#[tokio::main]
async fn main() {
    //注册日志
    let timer = LocalTime::new(format_description!(
        "[year]-[month padding:zero]-[day padding:zero] [hour]:[minute]:[second]"
    ));
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::ERROR) // 设置最大日志级别为INFO
        .with_timer(timer)
        .pretty()
        .with_ansi(false)
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");
    run_server().await
}
