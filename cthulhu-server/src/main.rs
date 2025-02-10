use std::{net::SocketAddr, str::FromStr, sync::Arc, time::Duration};

use async_once_cell::OnceCell;

use clap::{arg, ArgAction};
use clap::builder::Str;
use futures::stream::SplitSink;


use hyper::{upgrade::Upgraded, Body, Uri};

use hyper_tungstenite::tungstenite::Message;
use lazy_static::lazy_static;
use local_ip_address::local_ip;
use markup5ever::tendril::fmt::Slice;

use moka::future::Cache;
use net_proxy::{certificate_authority::RcgenAuthority, CustomProxy};
use rand::{rngs::StdRng, Rng};
use reqwest::redirect;
use rsa::signature::digest::consts::U6;
use time::macros::format_description;

use tokio_tungstenite::WebSocketStream;
use tracing::Level;
use tracing_subscriber::{fmt::time::LocalTime, FmtSubscriber};

use rustls_pemfile as pemfile;
use serde::Deserialize;
use user_agent_parser::UserAgentParser;

use crate::{
    net_proxy::AddrListenerServer,
};
use crate::net_proxy::{HttpHandler, WebSocketHandler};
// mod core;
// mod handle;

mod ja3;
// mod jsbind;
mod net_proxy;
mod proxy;
mod rcgen;
mod utils;

mod macros;

type NetClient = reqwest::Client;
type AppProxy<'ca, P> = CustomProxy<RcgenAuthority, Handler, Handler, P>;

type Sink = SplitSink<WebSocketStream<Upgraded>, Message>;
#[derive(Debug, Clone, Hash, PartialEq, Eq, Default, Deserialize)]
pub struct ProxyCfg {
    pub ja3: Option<i64>,
    pub h2: Option<i64>,
    pub port: Option<u16>,
    pub proxy: Option<String>,
}


#[derive(Clone, Debug)]
pub struct Handler;
impl HttpHandler for Handler {}
impl WebSocketHandler for Handler {}
// const TIME_FMT: &str = "%Y-%m-%d %H:%M:%S";
lazy_static! {



    ///客户端池
    pub static ref CLITENT_POOL: Cache<ProxyCfg,NetClient> =Cache::builder()
    .max_capacity(10000)
    .time_to_live(std::time::Duration::from_secs(60*10))
    .build();
 ///配置
    pub static ref PROXY_CONFIG: ProxyCfg = {
        let json = utils::read_bytes("./cfg.json").expect("读取配置文件失败!");
        let json =String::from_utf8(json).unwrap();
        let proxy=serde_json::from_str::<ProxyCfg>(&json).expect("配置文件格式错误");
        proxy
    };
    ///sever http客户端
    pub static ref HTTP_CLIENT: NetClient = {
        let client= create_client(PROXY_CONFIG.clone());
        client
    };

    pub static ref IS_SYS_PROXY:std::sync::RwLock<bool>=std::sync::RwLock::new(false);

    //CA证书
    pub static ref AUTH:OnceCell< Arc <RcgenAuthority>>=OnceCell::new();


}

pub async fn reqwest_response_to_hyper(
    res: reqwest::Response,
) -> Result<hyper::Response<Body>, Box<dyn std::error::Error>> {
    let status = res.status();
    let version = res.version();
    let headers = res.headers().clone();

    let bytes = res.bytes().await?;
    let mut response = hyper::Response::builder()
        .version(version)
        .status(status)
        .body(Body::from(bytes))?;
    *response.headers_mut() = headers;
    Ok(response)
}

pub async fn reqwest_request_from_hyper(req: hyper::Request<Body>) -> reqwest::Request {
    let (parts, body) = req.into_parts();
    let mut request = reqwest::Request::new(
        parts.method,
        reqwest::Url::from_str(&parts.uri.to_string()).unwrap(),
    );

    *request.headers_mut() = parts.headers;
    *request.version_mut() = parts.version;
    let bytes = hyper::body::to_bytes(body).await.unwrap();
    *request.body_mut() = Some(reqwest::Body::from(bytes));
    request
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

fn create_client(key: ProxyCfg) -> NetClient {
    let client_config = ja3::random_ja3(key.ja3.unwrap_or(0) as usize);

    let mut builder = reqwest::ClientBuilder::new()
        .timeout(Duration::from_secs(60 * 60)) //一小时
        .connect_timeout(Duration::from_secs(60)) //一分钟
        .http2_keep_alive_timeout(Duration::from_secs(60))
        .pool_max_idle_per_host(3 * 60 * 1000)
        .redirect(redirect::Policy::limited(100))
        .use_preconfigured_tls(client_config)
        .danger_accept_invalid_certs(true);
    let port = PROXY_CONFIG.port.unwrap_or(3000);

    if proxy::already_sys_proxy(port as u16, local_ip().ok()) {
        //避免环回代理
        builder = builder.no_proxy(); //禁用自动添加系统代理
    }
    let h2=key.h2.unwrap_or(0);
    if h2 != 0 {
        let mut random: StdRng = rand::SeedableRng::seed_from_u64(h2.abs_diff(0));
        let base = 1024 * 1024; //1mb
        builder = builder
            .http2_max_frame_size(random.gen_range(16_384..((1 << 24) - 1)) / 1024 * 1024)
            // .http2_max_send_buf_size(random.gen_range(2..20) * base)
            .http2_initial_connection_window_size(random.gen_range(2..20) * base as u32)
            .http2_initial_stream_window_size(random.gen_range(2..20) * base as u32);
    }
    if let Some(uri) = key.proxy {
        let proxy = reqwest::Proxy::all(&uri.to_string()).unwrap();
        builder = builder.proxy(proxy);
    }
    builder.build().unwrap()
}
async fn get_client(addr: SocketAddr, uri: Uri) -> NetClient {
    // let key = {
    //     let mut random = rand::thread_rng();
    //     ProxyData {
    //         proxy: None,
    //         ja3: random.gen_range(1..500),
    //         h2: random.gen_range(1..500),
    //     }
    // };
    // let key = &key;
    //=======

    HTTP_CLIENT.clone()
}

async fn run_server() {
    let port = PROXY_CONFIG.clone().port.unwrap_or(3000);
    //初始化ca证书
    let _ = AUTH
        .get_or_init(async {
            let key = utils::read_bytes("./ca/ca.key").expect("读取密钥文件失败!");
            let cert = utils::read_bytes("./ca/ca.cer").expect("读取证书文件失败!");

            let mut private_key_bytes: &[u8] = key.as_bytes();
            let mut ca_cert_bytes: &[u8] = cert.as_bytes();

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

            Arc::new(
                RcgenAuthority::new(private_key.into(), ca_cert, 1_000)
                    .expect("Failed to create Certificate Authority"),
            )
        })
        .await;

    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    let rustls = tokio_tungstenite::Connector::Rustls(Arc::new(ja3::random_ja3(0)));
    let proxy = AppProxy::new(
        AUTH.get().unwrap().clone(),
        AddrListenerServer::Addr(addr),
        Handler,
        Handler,
        Some(rustls),
        get_client,
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
    //初始化环境变量
    // dotenv::dotenv().ok();

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
                proxy::set_system_proxy(true, "127.0.0.1:3000", "").map_err(|e| e.to_string()).unwrap();
                println!("设置系统代理成功");
            }
            run_server().await
        }
        Some(("cagen", subcmd)) => {
            let dir = subcmd.get_one::<String>("DIR").unwrap();
            rcgen::ca_gen(dir);
        }
        Some((c, _)) => println!("unknown option {c}"),
        None => {
            println!("unknown option")
        }
    }
}
