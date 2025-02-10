use std::{
    any::Any,
    collections::{HashMap, HashSet},
    fmt::Debug,
    net::SocketAddr,
    sync::{Arc, Condvar},
    time::Duration,
};

use hyper::http::Uri;
use rquickjs::{AsyncContext, AsyncRuntime};
use serde::Deserialize;
use sled::Db;
use tokio::sync::{Mutex, RwLock};

use crate::{
    handle::model::Plugin,
    jsbind::{self, server::Scope},
    utils, Sink,
};



#[derive(Debug, Default)]
pub struct ClientManager {
    //session id map sink
    pub sinks: RwLock<HashMap<String, Mutex<Sink>>>,

    //客户端标识 映射 websocket Sink
    pub sessions: RwLock<HashMap<Scope, HashSet<String>>>,

    ///客户端标识 映射 代理key
    pub proxy_datas: RwLock<HashMap<Scope, ProxyCfg>>,
    //客户端对应的标志地址和信号，用来阻塞请求
    pub locks: RwLock<HashMap<Scope, Arc<(std::sync::Mutex<bool>, Condvar)>>>,
    //一次请求中 其所在的域
    pub ctx_map_scope_keys: RwLock<HashMap<(SocketAddr, Uri), Scope>>,
    //id map scope
    pub scope_keys: RwLock<HashMap<String, Scope>>,
}

impl ClientManager {
    pub async fn set_scope_key(&self, key: Scope) {
        let mut guard = self.scope_keys.write().await;
        guard.insert(key.id.clone(), key);
    }
    pub async fn add_session_sink(&self, scope_key: Scope, session_id: String, sink: Sink) {
        let mut guard = self.sessions.write().await;
        let sessions = match guard.get_mut(&scope_key) {
            Some(v) => v,
            None => {
                guard.insert(scope_key.clone(), HashSet::new());
                guard.get_mut(&scope_key).unwrap()
            }
        };
        sessions.insert(session_id.clone());
        let mut guard = self.sinks.write().await;
        guard.insert(session_id, Mutex::new(sink));
    }

    pub async fn set_proxy(&self, scope_key: Scope, proxy_cfg: ProxyCfg) {
        let mut guard = self.proxy_datas.write().await;
        guard.insert(scope_key, proxy_cfg);
    }
}

pub struct PluginCtx {
    pub plugin: Plugin,
    pub ctx: Option<Mutex<AsyncContext>>,
    pub rt: Option<AsyncRuntime>,
    pub db: Option<Db>,
}
impl Debug for PluginCtx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PluginCtx")
            .field("plugin", &self.plugin)
            .field("ctx", &self.ctx.type_id())
            .field("rt", &self.rt.type_id())
            .field("db", &self.db)
            .finish()
    }
}
impl PluginCtx {
    pub async fn new(plugin: Plugin) -> Result<Self, String> {
        if plugin.server_path.is_empty() {
            return Ok(Self {
                plugin,
                ctx: None,
                rt: None,
                db: None,
            });
        }
        let (ctx, rt, db) = jsbind::content(&plugin).await?;
        println!("loaded plugin: {}, ID = '{}'", &plugin.name, &plugin.id);
        let ctx = Mutex::new(ctx);
        Ok(Self {
            plugin,
            ctx: Some(ctx),
            rt: Some(rt),
            db: Some(db),
        })
    }
}

#[derive(Default)]
pub struct PluginManager {
    //插件id 映射 对应的js上下文
    pub ctxs: RwLock<HashMap<String, Arc<PluginCtx>>>,
}

impl PluginManager {
    pub async fn ctxs_by_host(
        &self,
        host: &str,
    ) -> (
        Vec<Arc<PluginCtx>>,
        Vec<Arc<PluginCtx>>,
        Option<Arc<PluginCtx>>,
    ) {
        let guard = self.ctxs.read().await;
        let mut matched_ctxs = vec![];
        let mut net_monitor_ctxs = vec![];
        let mut net_modify_ctxs = vec![];
        guard
            .iter()
            .filter(|(_k, ctx)| {
                if ctx.plugin.server_path.is_empty() {
                    return false;
                }
                let matches = &ctx.plugin.matches;
                matches.is_empty() || matches.split(",").any(|m| utils::mini_match(m, host))
            })
            .map(|(_k, v)| v.clone())
            .for_each(|ctx| {
                if ctx.plugin.net_monitor == 1 {
                    net_monitor_ctxs.push(ctx.clone())
                }
                if ctx.plugin.net_modify >= 1 {
                    net_modify_ctxs.push(ctx.clone())
                }
                matched_ctxs.push(ctx);
            });
        net_modify_ctxs.sort_by(|a, b| {
            a.plugin
                .net_modify
                .cmp(&b.plugin.net_modify)
                .then_with(|| a.plugin.install_time.cmp(&b.plugin.install_time).reverse())
        });
        (matched_ctxs, net_monitor_ctxs, net_modify_ctxs.pop())
    }

    pub async fn set_ctx(&self, ctx: PluginCtx) -> Arc<PluginCtx> {
        let ctx = Arc::new(ctx);
        let mut guard = self.ctxs.write().await;
        guard.insert(ctx.plugin.id.clone(), ctx.clone());
        ctx
    }

    pub async fn get_ctx(&self, id: &str) -> Option<Arc<PluginCtx>> {
        let guard = self.ctxs.read().await;
        let ctx = guard.get(id)?;
        Some(ctx.clone())
    }

    pub async fn del_ctx(&self, id: &str) -> Option<Arc<PluginCtx>> {
        let mut guard = self.ctxs.write().await;
        guard.remove(id)
    }
}

pub struct AsyncTaskManager {
    pub tasks: Arc<RwLock<Vec<tokio::task::JoinHandle<()>>>>,
    _interval_task: tokio::task::JoinHandle<()>,
}
impl AsyncTaskManager {
    pub fn new() -> Self {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        let tasks = Arc::new(RwLock::new(vec![]));
        let tasks_clone = tasks.clone();
        let interval_task = async move {
            loop {
                let _ins = interval.tick().await;
                let mut tasks = tasks.write().await;
                tasks.retain(|v: &tokio::task::JoinHandle<()>| !v.is_finished())
            }
        };
        let interval_task: tokio::task::JoinHandle<()> = tokio::spawn(interval_task);
        Self {
            tasks: tasks_clone,
            _interval_task: interval_task,
        }
    }
}

// mod test {
//     use crate::utils;

//     #[test]
//     pub fn te() {
//         let path = "./brith.text";
//         let month = 1..13;
//         let day = 1..32;
//         let call = move |y: i32| {
//             let y = format!("{:0>2}", y);
//             for m in month {
//                 let m = format!("{:0>2}", m);
//                 for d in day.clone() {
//                     let d = format!("{:0>2}", d);
//                     let ymd = format!("{y}{m}{d}\n");
//                     utils::write_bytes(path, ymd.as_bytes(), Some(true)).unwrap();
//                 }
//             }
//         };
//         for y in 80..99 {
//             (call.clone())(y);
//         }
//         for y in 0..25 {
//             (call.clone())(y);
//         }

//     }
// }
