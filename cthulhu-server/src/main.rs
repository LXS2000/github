use std::{fs, net::SocketAddr, sync::Arc, time::Duration};

use async_trait::async_trait;

use clap::{arg, ArgAction};
use http_body_util::BodyExt;
use hyper::{
    header::{HeaderValue, ACCEPT_ENCODING, CONTENT_ENCODING},
    Method, Request, Response, Uri,
};

use hyper_rustls::HttpsConnector;
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::TokioExecutor,
};
use lazy_static::lazy_static;
use local_ip_address::local_ip;

use net_proxy::{
    body::Body, certificate_authority::RcgenAuthority, HttpContext, HttpHandler, Proxy,
    RequestOrResponse, WebSocketHandler,
};

use rcgen::{CertificateParams, KeyPair};

use rustls_pki_types::UnixTime;
use serde::Deserialize;

use time::macros::format_description;
use tokio_rustls::rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::aws_lc_rs,
    pki_types::ServerName,
    ClientConfig, DigitallySignedStruct, SignatureScheme,
};
use tracing::Level;
use tracing_subscriber::{fmt::time::LocalTime, FmtSubscriber};

mod ja3;
mod net_proxy;
mod proxy;
mod rcgen_ca;
mod utils;

mod macros;

type NetClient = Client<HttpsConnector<HttpConnector>, Body>;
// type NetClient = reqwest::Client;
// type AppProxy<'ca> = Proxy<RcgenAuthority, Handler, Handler>;

// const TIME_FMT: &str = "%Y-%m-%d %H:%M:%S";
lazy_static! {



    ///sever http客户端
    pub static ref HTTP_CLIENT: NetClient = {

        let mut conn = HttpConnector::new();
        conn.enforce_http(false);
        let conn = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(ClientConfig::builder().dangerous().with_custom_certificate_verifier(Arc::new(NoVerifier)).with_no_client_auth())
            .https_or_http()
            .enable_all_versions()
            .wrap_connector(conn);
        let client = Client::builder(TokioExecutor::new())
            .pool_idle_timeout(Duration::from_secs(30))
            .http2_only(true)
            .build(conn);
        client
    };
    pub static ref IS_SYS_PROXY:std::sync::RwLock<bool>=std::sync::RwLock::new(false);


    pub static ref CONFIG:Config={
        let bytes = fs::read("./config.json").expect("配置文件读取失败");
        let cfg = serde_json::from_slice::<Config>(&bytes).expect("配置文件格式不正确");
        cfg
    };

}

#[derive(Debug)]
pub(crate) struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls_pki_types::CertificateDer<'_>,
        intermediates: &[rustls_pki_types::CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, tokio_rustls::rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install CTRL+C signal handler");

    println!("exit...");
}

fn get_cmd() -> clap::Command {
    clap::Command::new("cthulhu")
        .about("a high performance packet capture proxy server")
        .author("li xiu shun 3451743380@qq.com")
        .arg_required_else_help(true)
        .allow_external_subcommands(true)
        .subcommand(
            clap::Command::new("run").about("run the server").arg(
                arg!(sys: -s "set server to be system proxy")
                    .required(false)
                    .action(ArgAction::SetTrue),
            ),
        )
        .subcommand(
            clap::Command::new("cagen")
                .about("generate self signed cert with random privkey")
                .arg(
                    arg!(<DIR> "cert file output dir")
                        .required(false)
                        .default_missing_value("./ca/")
                        .default_value("./ca/"),
                ),
        )
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

impl HttpHandler for Handler {
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        mut req: Request<Body>,
    ) -> RequestOrResponse {
        req.headers_mut().remove(ACCEPT_ENCODING);
        if req.method() == Method::CONNECT {
            return req.into();
        }
        let uri = req.uri().clone();
        let version = req.version();
        println!("req:{},{:?},{}", req.method(), &version, uri.to_string());

        let headers = req.headers_mut();

        let host_ = uri.host().unwrap();
        let mut is_matched = false;
        for Match {
            host,
            ja3,
            akamai,
            proxy,
        } in &CONFIG.matches
        {
            if utils::mini_match(&host, host_) {
                headers.append("mitm-uri", HeaderValue::from_str(&uri.to_string()).unwrap());
                headers.append(
                    "mitm-version",
                    HeaderValue::from_str(&format!("{:?}", version)).unwrap(),
                );
                headers.append(
                    "mitm-proxy",
                    HeaderValue::from_str(&proxy.clone().unwrap_or_default()).unwrap(),
                );
                headers.append("mitm-akamai", HeaderValue::from_str(akamai).unwrap());
                headers.append("mitm-ja3", HeaderValue::from_str(ja3).unwrap());
                is_matched = true;
                break;
            }
        }
        if !is_matched {
            return req.into();
        }
        // let is_test = req.uri().to_string() == "https://browserleaks.com/css/style.css?v=86540715";
        *req.uri_mut() = Uri::from_static("https://127.0.0.1:520/");
        // req.headers_mut().remove(HOST);
        // let req = decode_request(req).unwrap();
        let call = HTTP_CLIENT.clone().request(req).await;
        match call {
            Ok(res) => {
                // if is_test {
                //     println!("{:?}", res.version());
                //     let body = res.collect().await.unwrap();
                //     let body: String = String::from_utf8(body.to_bytes().to_vec()).unwrap();
                //     // let body = String::from_utf8(body.to_vec()).unwrap();
                //     println!("body:\n{}", body);
                //     return Response::new(Body::empty()).into();
                // }
                let mut res = res.map(Body::from);
                res.headers_mut().remove(CONTENT_ENCODING);
                // let res=decode_response(res).unwrap();
                res.into()
            }
            Err(e) => {
                tracing::error!("{:?} uri:{}", &e, &uri);
                let res = Response::builder()
                    .status(500)
                    .body(Body::from(e.to_string()))
                    .unwrap();
                res.into()
            }
        }
    }
}

#[async_trait]
impl WebSocketHandler for Handler {}

fn read_ca() -> RcgenAuthority {
    let key = utils::read_bytes("./ca/ca.key").expect("读取密钥文件失败!");
    let cert = utils::read_bytes("./ca/ca.cer").expect("读取证书文件失败!");

    let key_pair =
        KeyPair::from_pem(&String::from_utf8(key).unwrap()).expect("Failed to parse private key");
    let ca_cert = CertificateParams::from_ca_cert_pem(&String::from_utf8(cert).unwrap())
        .expect("Failed to parse CA certificate")
        .self_signed(&key_pair)
        .expect("Failed to sign CA certificate");

    let ca = RcgenAuthority::new(key_pair, ca_cert, 1_000, aws_lc_rs::default_provider());

    ca
}
async fn run_server() {
    //初始化ca证书
    let port = CONFIG.port;
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let ca = read_ca();
    // let rustls = tokio_tungstenite::Connector::Rustls(Arc::new(ja3::random_ja3(0)));
    let proxy = Proxy::builder()
        .with_addr(addr)
        .with_ca(ca)
        .with_rustls_client(aws_lc_rs::default_provider())
        .with_http_handler(Handler)
        .with_websocket_handler(Handler)
        .with_graceful_shutdown(shutdown_signal())
        .build()
        .expect("Failed to create proxy");

    let local_ip = auto_result!(local_ip(),err=>{
        panic!("获取本机内网地址失败：{}",err);
    });
    println!("server at port {local_ip}:{port}");
    if let Err(e) = proxy.start().await {
        panic!("{}", e);
    }
}

#[tokio::main]
async fn main() {
    //初始化命令行工具
    let cmd = get_cmd();

    let matches = cmd.get_matches();
    let subcmd = matches.subcommand();
    match subcmd {
        Some(("run", subcmd)) => {
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

            tracing::subscriber::set_global_default(subscriber)
                .expect("setting default subscriber failed");

            //注册系统代理
            if subcmd.get_flag("sys") {
                let port = CONFIG.port;
                let addr = format!("127.0.0.1:{}", port);
                proxy::set_system_proxy(true, addr.as_str(), "")
                    .map_err(|e| e.to_string())
                    .unwrap();
                println!("设置系统代理成功");
            }
            run_server().await
        }
        Some(("cagen", subcmd)) => {
            let dir = subcmd.get_one::<String>("DIR").unwrap();
            rcgen_ca::ca_gen(dir);
        }
        Some((c, _)) => println!("unknown option {c}"),
        None => {
            println!("unknown option")
        }
    }

    run_server().await
}
#[tokio::test]
async fn test() {
    //初始化环境变量
    // dotenv::dotenv().ok();

    // let a = mini_match("a.b.c", "a.b.c");
    // println!("{}", a)
    let res = HTTP_CLIENT
        .request(
            Request::builder()
                .uri(Uri::from_static(
                    "https://browserleaks.com/css/style.css?v=86540715",
                ))
                .method(Method::GET)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    println!("headers:{:#?}", res.headers());
    println!("{}", "");
    let body = res.collect().await.unwrap();
    let body: String = String::from_utf8(body.to_bytes().to_vec()).unwrap();
    // let body = String::from_utf8(body.to_vec()).unwrap();
    println!("body:\n{}", body);
}
