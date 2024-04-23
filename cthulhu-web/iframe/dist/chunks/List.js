import{I as g}from"./IconBtn.js";import{_ as L,b as z,u as I,j as _,c as x,C as v,r as k,o as h,d as y,e as n,t as b,f as u,g as p,k as V,q as C,n as N,E as M,v as O,w as U,F as j,l as q,p as G,h as R}from"../assets/index.js";import{b as T,d as A,r as J,e as K,g as Q}from"./api.js";import{L as D}from"./local.js";import"./SvgIcon.js";const X="https://web.cthulhu.server/iframe/assets/logo.png";const Y={class:"col",style:{height:"100%",width:"100%"}},Z={class:"row head"},ee=["src"],te={class:"name"},ne={class:"version"},oe={class:"row",style:{height:"80%"}},ie={class:"col",style:{width:"90%"}},le={class:"intro row"},se={class:"row-between"},re={class:"id"},ae={class:"col-between",style:{width:"10%",height:"90%","margin-top":"auto"}},ue={class:"row-between",style:{height:"20%","margin-top":"auto","align-items":"center"}},de={key:0,class:"row-between",style:{width:"60%",margin:"auto"}},ce={__name:"Plugin",props:{plugin:{}},emits:["onDelete"],setup(e,{emit:s}){const r=new D({whetherDel:{zh:"是否删除此插件？",en:"Do you want to delete this plugin？"}}),i=r.tlp.bind(r);r.tlf.bind(r),r.tl.bind(r);const a=e,f=s,l=z();let c=I();_("");const m=_(window.innerWidth/window.innerHeight),P=x(()=>({margin:m.value<=v.ratio?"0.2rem auto":"0.2rem 0",width:m.value<=v.ratio?"90%":"45%"})),w=x(()=>a.plugin.logoPath?a.plugin.logoPath.toString().startsWith("http")?a.plugin.logoPath:T(a.plugin.id,a.plugin.logoPath):X),S=o=>{if(c.commit("curPlugin",o),window.innerWidth/window.innerHeight<v.ratio){l.push("/sub/log");return}l.push("/index/sub/log")},B=o=>{if(c.commit("curPlugin",o),window.innerWidth/window.innerHeight<v.ratio){l.push("/sub/func");return}l.push("/index/sub/func")},H=o=>{if(c.commit("curPlugin",o),window.innerWidth/window.innerHeight<v.ratio){l.push("/sub/store");return}l.push("/index/sub/store")};function W(o){M.alert(i("{whetherDel}？"),i("{warning}"),{confirmButtonText:i("{sure}")}).then(t=>A({id:o}).then($=>{f("onDelete",o)}))}function E(o){return J({id:o})}function F(o){return K({id:o})}return window.addEventListener("resize",()=>{m.value=window.innerWidth/window.innerHeight}),(o,t)=>{const $=k("el-switch");return h(),y("div",{class:"plugin col",style:N(P.value)},[n("div",Y,[n("div",Z,[n("img",{src:w.value,alt:"logo",class:"logo"},null,8,ee),n("span",te,b(e.plugin.name),1),n("span",ne,"Version："+b(e.plugin.version),1)]),n("div",oe,[n("div",ie,[n("div",le,b(e.plugin.intro),1),n("div",se,[n("span",re,"ID："+b(e.plugin.id),1)])]),n("div",ae,[u(g,{size:1.2,name:"flush",color:"#62da59",onClick:t[0]||(t[0]=d=>E(e.plugin.id)),prompt:p(i)("{reload}")},null,8,["prompt"]),u(g,{size:1.2,name:"delete",color:"#fc6868",onClick:t[1]||(t[1]=d=>W(e.plugin.id)),prompt:p(i)("{del}")},null,8,["prompt"])])]),n("div",ue,[e.plugin.enable?(h(),y("div",de,[e.plugin.webIndex?(h(),V(g,{key:0,size:1.2,name:"func",color:"#59a9da",onClick:t[2]||(t[2]=d=>B(e.plugin)),prompt:p(i)("{plugin} {func}")},null,8,["prompt"])):C("",!0),u(g,{size:1.2,name:"store",color:"#b058ef",onClick:t[3]||(t[3]=d=>H(e.plugin)),prompt:p(i)("{plugin} {stores}")},null,8,["prompt"]),u(g,{size:1.2,name:"log",color:"#d5d5d5",onClick:t[4]||(t[4]=d=>S(e.plugin)),prompt:p(i)("{plugin} {logs}")},null,8,["prompt"])])):C("",!0),u($,{modelValue:e.plugin.enable,"onUpdate:modelValue":t[5]||(t[5]=d=>e.plugin.enable=d),onClick:t[6]||(t[6]=d=>F(e.plugin.id)),"active-value":1,style:{"margin-left":"auto"}},null,8,["modelValue"])])])],4)}}},ge=L(ce,[["__scopeId","data-v-9ab74487"]]);const pe=e=>(G("data-v-1ee7acdf"),e=e(),R(),e),he={class:"col",style:{width:"98%","margin-left":"1%",height:"100%"}},me={id:"listHead",class:"row"},we={id:"plugins"},ve=pe(()=>n("div",{style:{height:"5rem"}},null,-1)),_e={__name:"List",setup(e){const s=new D({search:{zh:"输入关键字查询",en:"search with keyword"}},!0);s.tlp.bind(s),s.tlf.bind(s);const r=s.tl.bind(s);z(),I();const i=_(""),a=_([]);_(window.innerWidth/window.innerHeight),O(()=>{f()});function f(){Q().then(l=>{a.value=l})}return(l,c)=>{const m=k("el-input"),P=k("el-scrollbar");return h(),y("div",he,[n("div",me,[u(m,{modelValue:i.value,"onUpdate:modelValue":c[0]||(c[0]=w=>i.value=w),style:{width:"80%"},placeholder:p(r)("search")},null,8,["modelValue","placeholder"]),u(g,{size:1.2,name:"search",color:"#66cff5"})]),u(P,null,{default:U(()=>[n("div",we,[(h(!0),y(j,null,q(a.value,w=>(h(),V(ge,{plugin:w,onOnDelete:f},null,8,["plugin"]))),256))]),ve]),_:1})])}}},$e=L(_e,[["__scopeId","data-v-1ee7acdf"]]);export{$e as default};
