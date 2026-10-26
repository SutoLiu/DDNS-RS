const TK='ddns_token';
const FAMS=[['v4','ipv4'],['v6','ipv6']];
const URLS_V4=['https://ipv4.icanhazip.com','https://api.ipify.org','https://ddns.oray.com/checkip','https://ip.3322.net','https://v4.yinghualuo.cn/bejson','https://myip.ipip.net'];
const URLS_V6=['https://ipv6.icanhazip.com','https://speed.neu6.edu.cn/getIP.php','https://v6.ident.me','https://6.ipw.cn','https://v6.yinghualuo.cn/bejson'];
const TTL_OPTS=[[0,'ttl.auto'],[1,'ttl.1s'],[5,'ttl.5s'],[10,'ttl.10s'],[60,'ttl.1m'],[120,'ttl.2m'],[600,'ttl.10m'],[1800,'ttl.30m'],[3600,'ttl.1h']];

let token=localStorage.getItem(TK)||'';
let lang='zh-cn',langDirty=false;
let cfg=null,setup=false,monitorOk=true,siteTitle='DDNS-RS';
let ed=null,edIdx=-1;
let ifacesCache=[];
let lastEntriesHtml='',lastLogKey='';
let toastTimer=null,confirmCb=null;

const $=id=>document.getElementById(id);
const onEnter=f=>e=>{if(e.key==='Enter')f(e)};
const ESC_MAP={'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'};
function esc(s){return String(s??'').replace(/[&<>"']/g,c=>ESC_MAP[c])}
function show(id){document.querySelectorAll('.view').forEach(e=>e.hidden=true);$(id).hidden=false}
function openModal(id){$(id).hidden=false}
function closeModal(id){$(id).hidden=true}
function showToast(msg,ms=1500){
  const t=$('toast');
  t.textContent=msg;t.classList.add('show');
  if(toastTimer)clearTimeout(toastTimer);
  toastTimer=setTimeout(()=>t.classList.remove('show'),ms);
}
function fmtTime(secs){
  if(!secs)return '-';
  const d=new Date(secs*1000),p=n=>String(n).padStart(2,'0');
  return `${p(d.getMonth()+1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}
function setToggle(btn,on){btn.classList.toggle('on',!!on)}
function getToggle(btn){return btn.classList.contains('on')}
const setSegEl=(el,val)=>el.querySelectorAll('button').forEach(b=>b.classList.toggle('on',b.dataset.v===val));
const getSegEl=el=>el.querySelector('button.on')?.dataset.v||'';
const setSeg=(id,val)=>setSegEl($(id),val);
const getSeg=id=>getSegEl($(id));
function addOpt(sel,val,label){const o=document.createElement('option');o.value=val;o.textContent=label;sel.appendChild(o)}
function ensureOpt(sel,val,label){if(![...sel.options].some(o=>o.value===val))addOpt(sel,val,label||val)}

let lastAct=performance.now();
['pointerdown','keydown','wheel'].forEach(ev=>document.addEventListener(ev,()=>{lastAct=performance.now()},{passive:true}));
window.addEventListener('storage',e=>{if(e.key===TK&&e.newValue)token=e.newValue});
class AuthError extends Error{}
function timeoutSignal(ms){
  if(AbortSignal.timeout)return AbortSignal.timeout(ms);
  const c=new AbortController();setTimeout(()=>c.abort(),ms);return c.signal;
}
async function api(method,path,body,ms=10_000){
  const opts={method,headers:{},signal:timeoutSignal(ms)};
  if(token)opts.headers.Authorization='Bearer '+token;
  if(token&&performance.now()-lastAct<120_000)opts.headers['X-Auth-Active']='1';
  if(body!==undefined){opts.headers['Content-Type']='application/json';opts.body=JSON.stringify(body)}
  const res=await fetch(path,opts);
  const nt=res.headers.get('X-Auth-Token');
  if(nt){token=nt;localStorage.setItem(TK,nt)}
  if(res.status===401)throw new AuthError('登录已过期');
  if(!res.ok){
    let msg='HTTP '+res.status;
    try{msg=(await res.json()).error||msg}catch{}
    throw new Error(msg);
  }
  return res;
}
const getJson=async p=>(await api('GET',p)).json();
async function apiOk(method,path,body){return (await api(method,path,body)).json()}
function fail(e){e instanceof AuthError?location.reload():showToast(e.message)}

function setPoll(fn,ms){
  let t=null,busy=false,fails=0,down=false;
  const run=async()=>{
    if(busy)return;busy=true;
    try{await fn();fails=0;down=false}
    catch(e){
      if(e instanceof AuthError)return location.reload();
      if(++fails>=3&&!down){down=true;showToast(t_('toast.offline'))}
    }
    finally{busy=false}
  };
  const ctl={
    stop(){if(t){clearInterval(t);t=null}},
    resume(){ctl.stop();run();t=setInterval(run,ms)}
  };
  return ctl;
}
const infoPoll=setPoll(async()=>{renderStatus(await getJson('/api/status'))},2000);

const LANGS=[['zh-cn','简体中文'],['zh-tw','繁體中文'],['en','English']];
const I18N={
  'tab.status':{'zh-cn':'状态','zh-tw':'狀態','en':'Status'},
  'tab.tasks':{'zh-cn':'任务','zh-tw':'任務','en':'Tasks'},
  'tab.settings':{'zh-cn':'设置','zh-tw':'設定','en':'Settings'},
  'login.password':{'zh-cn':'密码','zh-tw':'密碼','en':'Password'},
  'login.setupPwd':{'zh-cn':'设置密码（至少 8 位）','zh-tw':'設定密碼（至少 8 位）','en':'Set password (min 8 chars)'},
  'login.confirm':{'zh-cn':'确认密码','zh-tw':'確認密碼','en':'Confirm password'},
  'login.login':{'zh-cn':'登录','zh-tw':'登入','en':'Sign in'},
  'login.setupBtn':{'zh-cn':'设置密码并登录','zh-tw':'設定密碼並登入','en':'Set and sign in'},
  'login.ok':{'zh-cn':'登录成功','zh-tw':'登入成功','en':'Signed in'},
  'login.pwdSet':{'zh-cn':'密码已设置','zh-tw':'密碼已設定','en':'Password set'},
  'login.tooShort':{'zh-cn':'密码至少 8 位','zh-tw':'密碼至少 8 位','en':'Password must be at least 8 characters'},
  'login.mismatch':{'zh-cn':'两次输入的密码不一致','zh-tw':'兩次輸入的密碼不一致','en':'Passwords do not match'},
  'st.overview':{'zh-cn':'概览','zh-tw':'概覽','en':'Overview'},
  'st.state':{'zh-cn':'运行状态','zh-tw':'執行狀態','en':'State'},
  'st.running':{'zh-cn':'更新中…','zh-tw':'更新中…','en':'Updating…'},
  'st.idle':{'zh-cn':'空闲','zh-tw':'閒置','en':'Idle'},
  'st.lastRun':{'zh-cn':'最近更新','zh-tw':'最近更新','en':'Last run'},
  'st.count':{'zh-cn':'任务数量','zh-tw':'任務數量','en':'Tasks'},
  'st.unit':{'zh-cn':'个','zh-tw':'個','en':''},
  'st.runNow':{'zh-cn':'立即更新','zh-tw':'立即更新','en':'Update now'},
  'st.logs':{'zh-cn':'日志','zh-tw':'日誌','en':'Logs'},
  'st.clear':{'zh-cn':'清空','zh-tw':'清空','en':'Clear'},
  'st.cleared':{'zh-cn':'日志已清空','zh-tw':'日誌已清空','en':'Logs cleared'},
  'st.empty':{'zh-cn':'暂无任务，请到「任务」页新增','zh-tw':'暫無任務，請到「任務」頁新增','en':'No tasks yet. Add one in Tasks'},
  'st.waiting':{'zh-cn':'等待检测','zh-tw':'等待偵測','en':'Awaiting check'},
  'st.notEnabled':{'zh-cn':'未启用','zh-tw':'未啟用','en':'Not enabled'},
  'st.disabled':{'zh-cn':'已停用','zh-tw':'已停用','en':'Disabled'},
  'st.unchanged':{'zh-cn':'地址未变化','zh-tw':'位址未變化','en':'Address unchanged'},
  'st.updated':{'zh-cn':'更新成功','zh-tw':'更新成功','en':'Updated'},
  'st.noip':{'zh-cn':'未获取到地址','zh-tw':'未取得位址','en':'No address found'},
  'lv.error':{'zh-cn':'错误','zh-tw':'錯誤','en':'Error'},
  'lv.warn':{'zh-cn':'警告','zh-tw':'警告','en':'Warn'},
  'lv.info':{'zh-cn':'信息','zh-tw':'資訊','en':'Info'},
  'tk.title':{'zh-cn':'解析任务','zh-tw':'解析任務','en':'DNS tasks'},
  'tk.add':{'zh-cn':'新增任务','zh-tw':'新增任務','en':'Add task'},
  'tk.empty':{'zh-cn':'还没有任务，点击右上角「新增任务」开始','zh-tw':'還沒有任務，點擊右上角「新增任務」開始','en':'No tasks yet. Tap "Add task" to start'},
  'tk.unnamed':{'zh-cn':'未命名任务','zh-tw':'未命名任務','en':'Untitled'},
  'tk.enable':{'zh-cn':'启用','zh-tw':'啟用','en':'Enable'},
  'tk.disable':{'zh-cn':'停用','zh-tw':'停用','en':'Disable'},
  'tk.edit':{'zh-cn':'编辑','zh-tw':'編輯','en':'Edit'},
  'tk.del':{'zh-cn':'删除','zh-tw':'刪除','en':'Delete'},
  'ed.back':{'zh-cn':'返回','zh-tw':'返回','en':'Back'},
  'ed.save':{'zh-cn':'保存','zh-tw':'儲存','en':'Save'},
  'ed.new':{'zh-cn':'新增任务','zh-tw':'新增任務','en':'Add task'},
  'ed.edit':{'zh-cn':'编辑任务','zh-tw':'編輯任務','en':'Edit task'},
  'ed.name':{'zh-cn':'名称','zh-tw':'名稱','en':'Name'},
  'ed.namePh':{'zh-cn':'备注名，便于识别','zh-tw':'備註名，便於識別','en':'Memo name'},
  'ed.enable':{'zh-cn':'启用','zh-tw':'啟用','en':'Enabled'},
  'ed.mode':{'zh-cn':'触发模式','zh-tw':'觸發模式','en':'Trigger'},
  'ed.interval':{'zh-cn':'轮询间隔','zh-tw':'輪詢間隔','en':'Interval'},
  'ed.watch':{'zh-cn':'监听网口','zh-tw':'監聽網口','en':'Watch interfaces'},
  'ed.watchPh':{'zh-cn':'网口名或通配符，留空为全部','zh-tw':'網口名或萬用字元，留空為全部','en':'Interface name or wildcard, empty for all'},
  'ed.zone':{'zh-cn':'根域名','zh-tw':'根網域','en':'Zone'},
  'ed.subs':{'zh-cn':'子域名','zh-tw':'子網域','en':'Subdomains'},
  'ed.subsPh':{'zh-cn':'home, vpn（留空或 @ 表示根域名）','zh-tw':'home, vpn（留空或 @ 表示根網域）','en':'home, vpn (empty or @ for zone)'},
  'ed.source':{'zh-cn':'来源','zh-tw':'來源','en':'Source'},
  'ed.provider':{'zh-cn':'服务商','zh-tw':'服務商','en':'Provider'},
  'ed.type':{'zh-cn':'类型','zh-tw':'類型','en':'Type'},
  'ed.proxied':{'zh-cn':'代理','zh-tw':'代理','en':'Proxied'},
  'ed.delete':{'zh-cn':'删除任务','zh-tw':'刪除任務','en':'Delete task'},
  'mode.poll':{'zh-cn':'轮询','zh-tw':'輪詢','en':'Poll'},
  'mode.listen':{'zh-cn':'监听','zh-tw':'監聽','en':'Listen'},
  'mode.hint.poll':{'zh-cn':'按设定间隔定期检测地址变化并自动更新','zh-tw':'按設定間隔定期偵測位址變化並自動更新','en':'Check for address changes at the set interval'},
  'mode.hint.listen':{'zh-cn':'监听本机地址变化事件，变化即触发更新','zh-tw':'監聽本機位址變化事件，變化即觸發更新','en':'Update instantly on local address changes'},
  'src.url':{'zh-cn':'接口','zh-tw':'介面','en':'API'},
  'src.if':{'zh-cn':'网卡','zh-tw':'網卡','en':'Interface'},
  'src.cmd':{'zh-cn':'命令','zh-tw':'命令','en':'Command'},
  'src.listHint':{'zh-cn':'按序回退：前一来源取不到地址自动尝试下一个','zh-tw':'按序回退：前一來源取不到位址自動嘗試下一個','en':'Ordered fallback: try the next source if one yields no address'},
  'src.ifPh':{'zh-cn':'网卡名或通配符，按序回退','zh-tw':'網卡名或萬用字元，按序回退','en':'Interface name or wildcard, ordered fallback'},
  'src.urlPh':{'zh-cn':'接口地址，按序回退','zh-tw':'介面位址，按序回退','en':'Endpoint URL, ordered fallback'},
  'src.cmdPh':{'zh-cn':'示例：curl -s https://api.ipify.org','zh-tw':'範例：curl -s https://api.ipify.org','en':'e.g. curl -s https://api.ipify.org'},
  'src.add':{'zh-cn':'添加来源','zh-tw':'新增來源','en':'Add source'},
  'ttl.auto':{'zh-cn':'自动（服务商默认）','zh-tw':'自動（服務商預設）','en':'Auto (provider default)'},
  'ttl.1s':{'zh-cn':'1 秒','zh-tw':'1 秒','en':'1s'},
  'ttl.5s':{'zh-cn':'5 秒','zh-tw':'5 秒','en':'5s'},
  'ttl.10s':{'zh-cn':'10 秒','zh-tw':'10 秒','en':'10s'},
  'ttl.1m':{'zh-cn':'1 分钟','zh-tw':'1 分鐘','en':'1m'},
  'ttl.2m':{'zh-cn':'2 分钟','zh-tw':'2 分鐘','en':'2m'},
  'ttl.10m':{'zh-cn':'10 分钟','zh-tw':'10 分鐘','en':'10m'},
  'ttl.30m':{'zh-cn':'30 分钟','zh-tw':'30 分鐘','en':'30m'},
  'ttl.1h':{'zh-cn':'1 小时','zh-tw':'1 小時','en':'1h'},
  'pv.aliyun':{'zh-cn':'阿里云','zh-tw':'阿里雲','en':'Aliyun'},
  'pv.aliesa':{'zh-cn':'阿里云ESA','zh-tw':'阿里雲ESA','en':'AliyunESA'},
  'pv.tencent':{'zh-cn':'腾讯云','zh-tw':'騰訊雲','en':'Tencent Cloud'},
  'pv.huawei':{'zh-cn':'华为云','zh-tw':'華為雲','en':'Huawei Cloud'},
  'pv.baidu':{'zh-cn':'百度云','zh-tw':'百度雲','en':'Baidu Cloud'},
  'pv.volcengine':{'zh-cn':'火山引擎','zh-tw':'火山引擎','en':'Volcengine'},
  'pv.cbUrl':{'zh-cn':'回调地址','zh-tw':'回調位址','en':'Callback URL'},
  'pv.cbUrlPh':{'zh-cn':'https://api.example.com/update?ip=#{ip}&domain=#{domain}','zh-tw':'https://api.example.com/update?ip=#{ip}&domain=#{domain}','en':'https://api.example.com/update?ip=#{ip}&domain=#{domain}'},
  'pv.cbBody':{'zh-cn':'请求体（可选）','zh-tw':'請求體（可選）','en':'Body (optional)'},
  'pv.cbBodyPh':{'zh-cn':'留空走 GET；如 {"ip":"#{ip}","domain":"#{domain}"}','zh-tw':'留空走 GET；如 {"ip":"#{ip}","domain":"#{domain}"}','en':'Empty for GET; e.g. {"ip":"#{ip}","domain":"#{domain}"}'},
  'pv.cbHint':{'zh-cn':'支持变量 #{ip}、#{domain}、#{recordType}、#{ttl}、#{timestamp}；请求体留空走 GET，合法 JSON 以 application/json 发送，否则为表单编码','zh-tw':'支持變數 #{ip}、#{domain}、#{recordType}、#{ttl}、#{timestamp}；請求體留空走 GET，合法 JSON 以 application/json 發送，否則為表單編碼','en':'Variables: #{ip}, #{domain}, #{recordType}, #{ttl}, #{timestamp}. Empty body sends GET; valid JSON sends application/json, otherwise form-encoded.'},
  'se.service':{'zh-cn':'服务','zh-tw':'服務','en':'Service'},
  'se.port':{'zh-cn':'端口','zh-tw':'連接埠','en':'Port'},
  'se.lan':{'zh-cn':'禁止公网','zh-tw':'禁止公網','en':'LAN only'},
  'se.lanHint':{'zh-cn':'开启后仅允许本机与局域网访问','zh-tw':'開啟後僅允許本機與區域網路存取','en':'Only localhost and LAN access when enabled'},
  'se.lang':{'zh-cn':'语言','zh-tw':'語言','en':'Language'},
  'se.tokenTtl':{'zh-cn':'自动登出','zh-tw':'自動登出','en':'Logout'},
  'se.ttlPh':{'zh-cn':'分钟','zh-tw':'分鐘','en':'min'},
  'se.ttlHint':{'zh-cn':'设置自动退出登录的时间，单位分钟','zh-tw':'設定自動登出的時間，單位分鐘','en':'Time before automatic logout, in minutes'},
  'se.log':{'zh-cn':'日志','zh-tw':'日誌','en':'Logs'},
  'se.logCap':{'zh-cn':'保留条数','zh-tw':'保留條數','en':'Keep'},
  'se.portJump':{'zh-cn':'端口已修改，正在跳转到新地址…','zh-tw':'連接埠已修改，正在跳轉到新位址…','en':'Port changed, redirecting…'},
  'se.save':{'zh-cn':'保存','zh-tw':'儲存','en':'Save'},
  'se.saved':{'zh-cn':'已保存','zh-tw':'已儲存','en':'Saved'},
  'se.site':{'zh-cn':'站点','zh-tw':'站點','en':'Site'},
  'se.title':{'zh-cn':'网站标题','zh-tw':'網站標題','en':'Site title'},
  'se.titlePh':{'zh-cn':'网站名称','zh-tw':'網站名稱','en':'Site name'},
  'se.titleEmpty':{'zh-cn':'标题不能为空','zh-tw':'標題不能為空','en':'Title cannot be empty'},
  'se.changePwd':{'zh-cn':'修改密码','zh-tw':'修改密碼','en':'Change password'},
  'se.others':{'zh-cn':'其他','zh-tw':'其他','en':'Others'},
  'se.about':{'zh-cn':'关于 DDNS-RS','zh-tw':'關於 DDNS-RS','en':'About DDNS-RS'},
  'se.logout':{'zh-cn':'退出登录','zh-tw':'登出','en':'Sign out'},
  'pw.title':{'zh-cn':'修改密码','zh-tw':'修改密碼','en':'Change password'},
  'pw.old':{'zh-cn':'原密码','zh-tw':'原密碼','en':'Current password'},
  'pw.new':{'zh-cn':'新密码（至少 8 位）','zh-tw':'新密碼（至少 8 位）','en':'New password (min 8 chars)'},
  'pw.new2':{'zh-cn':'确认新密码','zh-tw':'確認新密碼','en':'Confirm new password'},
  'pw.ok':{'zh-cn':'密码已修改，请重新登录','zh-tw':'密碼已修改，請重新登入','en':'Password changed. Sign in again'},
  'cancel':{'zh-cn':'取消','zh-tw':'取消','en':'Cancel'},
  'confirm':{'zh-cn':'确认','zh-tw':'確認','en':'Confirm'},
  'del.title':{'zh-cn':'删除确认','zh-tw':'刪除確認','en':'Confirm deletion'},
  'del.msg':{'zh-cn':'确认删除该任务？','zh-tw':'確認刪除該任務？','en':'Delete this task?'},
  'about.title':{'zh-cn':'关于','zh-tw':'關於','en':'About'},
  'about.tagline':{'zh-cn':'轻量动态域名解析服务','zh-tw':'輕量動態域名解析服務','en':'Lightweight DDNS service'},
  'about.usage':{'zh-cn':'使用','zh-tw':'使用','en':'Usage'},
  'about.u1':{'zh-cn':'「任务」页新增任务：选择服务商并填入其密钥，填写域名即可','zh-tw':'「任務」頁新增任務：選擇服務商並填入其金鑰，填寫網域即可','en':'Add a task in Tasks: pick a provider, enter its credentials and domain'},
  'about.u2':{'zh-cn':'地址变化后自动更新解析，无需手动干预','zh-tw':'位址變化後自動更新解析，無需手動干預','en':'Records update automatically when your address changes'},
  'about.u3':{'zh-cn':'「状态」页可查看各任务结果与运行日志','zh-tw':'「狀態」頁可查看各任務結果與執行日誌','en':'Check results and logs on the Status page'},
  'about.author':{'zh-cn':'作者','zh-tw':'作者','en':'Author'},
  'about.home':{'zh-cn':'主页','zh-tw':'主頁','en':'Homepage'},
  'about.version':{'zh-cn':'版本','zh-tw':'版本','en':'Version'},
  'st.support':{'zh-cn':'支持','zh-tw':'支援','en':'Support'},
  'st.donate':{'zh-cn':'支持开发','zh-tw':'支持開發','en':'Support development'},
  'donate.title':{'zh-cn':'支持开发','zh-tw':'支持開發','en':'Support development'},
  'donate.name':{'zh-cn':'请作者喝杯咖啡','zh-tw':'請作者喝杯咖啡','en':'Buy the author a coffee'},
  'donate.slogan':{'zh-cn':'你的支持是 ddns-rs 持续更新的动力','zh-tw':'你的支持是 ddns-rs 持續更新的動力','en':'Your support keeps ddns-rs improving'},
  'donate.pay':{'zh-cn':'付款方式','zh-tw':'付款方式','en':'Payment'},
  'toast.saved':{'zh-cn':'已保存','zh-tw':'已儲存','en':'Saved'},
  'toast.deleted':{'zh-cn':'已删除','zh-tw':'已刪除','en':'Deleted'},
  'toast.kicked':{'zh-cn':'已触发更新','zh-tw':'已觸發更新','en':'Update triggered'},
  'toast.offline':{'zh-cn':'连接已断开','zh-tw':'連線已中斷','en':'Connection lost'},
};
const t_=key=>{const d=I18N[key];return d?(d[lang]||d['zh-cn']||key):key};
const MSG_KEYS={'地址未变化':'st.unchanged','更新成功':'st.updated','未获取到地址':'st.noip'};
const fmtMsg=m=>MSG_KEYS[m]?t_(MSG_KEYS[m]):m;

function applyLang(){
  document.querySelectorAll('[data-i18n]').forEach(el=>{el.textContent=t_(el.dataset.i18n)});
  document.querySelectorAll('[data-i18n-ph]').forEach(el=>{el.placeholder=t_(el.dataset.i18nPh)});
  $('login-pass').placeholder=setup?t_('login.setupPwd'):t_('login.password');
  $('login-pass2').placeholder=t_('login.confirm');
  $('login-btn').textContent=setup?t_('login.setupBtn'):t_('login.login');
  document.documentElement.lang=lang;
  if(cfg)renderTasks();
}
function setLang(l){
  lang=l;
  lastLogKey='';lastEntriesHtml='';
  fillLangSelects();
  applyLang();
  if(token&&cfg&&cfg.lang!==lang)persistLang();
}
async function persistLang(){
  const next=JSON.parse(JSON.stringify(cfg));
  next.lang=lang;
  try{cfg=await apiOk('POST','/api/config',next)}catch(e){fail(e)}
}
function fillLangSelects(){
  for(const sel of[$('lg-lang'),$('se-lang')]){
    sel.innerHTML=LANGS.map(([v,n])=>`<option value="${v}">${n}</option>`).join('');
    sel.value=lang;
  }
}

function applyTitle(){
  document.title=siteTitle;
  $('login-name').textContent=siteTitle;
  $('about-name').textContent=siteTitle;
}

function doLogout(){
  if(!token)return;
  localStorage.removeItem(TK);
  token=null;
  location.reload();
}

async function showLogin(){
  token='';
  localStorage.removeItem(TK);
  infoPoll.stop();
  try{setup=(await getJson('/api/setup')).required}catch{setup=false}
  $('login-pass').value=$('login-pass2').value='';
  $('login-pass2').hidden=!setup;
  $('lg-lang').hidden=!setup;
  show('login');
  applyLang();
}

async function doLogin(){
  const pass=$('login-pass').value;
  if(!pass)return;
  if(setup&&pass!==$('login-pass2').value)return showToast(t_('login.mismatch'));
  try{
    const res=await api('POST',setup?'/api/setup':'/api/login',{pass});
    token=(await res.json()).token;
    localStorage.setItem(TK,token);
    showToast(setup?t_('login.pwdSet'):t_('login.ok'));
    await reload();
    if(langDirty&&cfg.lang!==lang)await persistLang();
    langDirty=false;
    show('app');
    switchTab('status');
    infoPoll.resume();
  }catch(e){fail(e)}
}

async function reload(){
  cfg=await getJson('/api/config');
  $('se-port').value=cfg.port;
  $('se-logcap').value=cfg.log_cap;
  $('se-ttl').value=Math.round(cfg.token_ttl/60);
  setToggle($('se-lan'),cfg.not_allow_wan);
  siteTitle=cfg.site_title||'DDNS-RS';
  applyTitle();
  seSync();
  renderTasks();
}

function seSync(){
  $('se-bar').hidden=+$('se-port').value===cfg.port&&getToggle($('se-lan'))===!!cfg.not_allow_wan&&+$('se-ttl').value===Math.round(cfg.token_ttl/60);
  $('log-bar').hidden=+$('se-logcap').value===cfg.log_cap;
}

function portJump(port){
  infoPoll.stop();
  showToast(t_('se.portJump'),3000);
  location.replace(location.protocol+'//'+location.hostname+':'+port+'/');
}

async function saveTitle(){
  const t=$('se-title-input').value.trim();
  if(!t)return showToast(t_('se.titleEmpty'));
  closeModal('modal-title');
  if(t===siteTitle)return;
  try{
    const next=JSON.parse(JSON.stringify(cfg));
    next.site_title=t;
    cfg=await apiOk('POST','/api/config',next);
    siteTitle=cfg.site_title;applyTitle();
    showToast(t_('se.saved'));
  }catch(e){fail(e)}
}

function modeChip(e){return e.mode==='listen'?t_('mode.listen'):t_('mode.poll')+' '+(e.interval||300)+'s'}

function renderStatus(s){
  monitorOk=s.listen_ok!==false;
  $('ov-state').textContent=s.busy?t_('st.running'):t_('st.idle');
  $('ov-run').textContent=fmtTime(s.last_run);
  $('ov-count').textContent=(s.entries.length+' '+t_('st.unit')).trim();
  $('ab-ver').textContent=s.version||'-';
  const html=s.entries.map(entryStatusCard).join('')||`<div class="card"><div class="empty">${esc(t_('st.empty'))}</div></div>`;
  if(html!==lastEntriesHtml){
    lastEntriesHtml=html;
    $('st-entries').innerHTML=html;
  }
  const key=s.logs.length+'|'+(s.logs.length?s.logs[0].time+'|'+s.logs[0].msg:'');
  if(key!==lastLogKey){
    lastLogKey=key;
    const box=$('st-logs');
    box.innerHTML=s.logs.slice().reverse().map(l=>`<div class="log-line ${l.level}"><span class="t">${fmtTime(l.time)}</span><span class="l">${l.level==='error'?t_('lv.error'):l.level==='warn'?t_('lv.warn'):t_('lv.info')}</span><span>${esc(l.msg)}</span></div>`).join('');
    box.scrollTop=box.scrollHeight;
  }
}

function entryStatusCard(e){
  const fam=(label,f,enabled)=>{
    if(!enabled)return `<div class="fam"><span class="k">${label}</span><span class="ip">-</span><span class="msg">${esc(t_('st.notEnabled'))}</span></div>`;
    const st=f.state||'idle';
    return `<div class="fam ${st==='err'?'err':''}"><span class="k">${label}</span><span class="ip">${esc(f.ip||'-')}</span><span class="msg">${esc(fmtMsg(f.message||t_('st.waiting')))}</span></div>`;
  };
  const bad=(e.v4_enabled&&e.ipv4.state==='err')||(e.v6_enabled&&e.ipv6.state==='err');
  const good=(e.v4_enabled&&e.ipv4.state==='ok')||(e.v6_enabled&&e.ipv6.state==='ok');
  const dot=!e.enabled?'idle':bad?'err':good?'ok':'idle';
  return `<div class="card">
<div class="entry-head"><span class="dot ${dot}"></span><span class="name">${esc(e.name)}</span><span class="chip">${esc(e.provider)}</span><span class="chip">${esc(modeChip(e))}</span>${e.enabled?'':`<span class="chip">${esc(t_('st.disabled'))}</span>`}</div>
<div class="entry-domains">${e.domains.map(esc).join(', ')}</div>
${fam('IPv4',e.ipv4,e.v4_enabled)}
${fam('IPv6',e.ipv6,e.v6_enabled)}
</div>`;
}

function renderTasks(){
  if(!cfg)return;
  $('tk-list').innerHTML=cfg.entries.length
    ?cfg.entries.map(taskCard).join('')
    :`<div class="card"><div class="empty">${esc(t_('tk.empty'))}</div></div>`;
}

function taskCard(e,i){
  const name=e.name||e.zone||t_('tk.unnamed');
  const subs=(e.sub_domains||'').split(/[\s,]+/).filter(Boolean);
  const list=(subs.length?subs:['@']).map(s=>s==='@'?e.zone:s+'.'+e.zone).join(', ');
  const kinds=[e.ipv4&&e.ipv4.enabled?'IPv4':'',e.ipv6&&e.ipv6.enabled?'IPv6':''].filter(Boolean).join('/');
  return `<div class="card">
<div class="entry-head"><span class="dot ${e.enabled?'ok':'idle'}"></span><span class="name">${esc(name)}</span><span class="chip">${esc(e.provider.type)}</span>${kinds?`<span class="chip">${kinds}</span>`:''}<span class="chip">${esc(modeChip(e))}</span></div>
<div class="entry-domains">${esc(list)}</div>
<div class="card-actions">
<div class="btn-row">
<button class="btn-outline btn-danger" data-del="${i}">${t_('tk.del')}</button>
<button class="btn-outline" data-tg="${i}">${e.enabled?t_('tk.disable'):t_('tk.enable')}</button>
<button class="btn" data-edit="${i}">${t_('tk.edit')}</button>
</div>
</div>
</div>`;
}

async function toggleEntry(i){
  cfg.entries[i].enabled=!cfg.entries[i].enabled;
  try{
    cfg=await apiOk('POST','/api/config',cfg);
    renderTasks();
    infoPoll.resume();
  }catch(e){fail(e);await reload()}
}

const SRC_FIELD={netInterface:'name',cmd:'cmd',url:'url'};
const SRC_KEY={netInterface:'src.if',cmd:'src.cmd',url:'src.url'};
const makeSrc=(type,val)=>({type,[SRC_FIELD[type]]:val});
const srcVals=s=>s[SRC_FIELD[s.type]]??'';
const srcBlank=v=>Array.isArray(v)?!v.length:!v.trim();
const syncBlocks=list=>[...list.children].forEach((r,i,rs)=>{
  const n=rs.length,ops=r.querySelector('.src-ops');
  r.querySelector('.src-num').textContent=n>1?' '+(i+1):'';
  ops.querySelector('.chips-up').hidden=i===0;
  ops.querySelector('.chips-down').hidden=i===n-1;
  ops.querySelector('.chips-del').hidden=i===0;
});
const defaultSrc=fam=>({type:'netInterface',name:[(ifacesCache.find(x=>x[fam])||{}).name].filter(Boolean)});

async function loadIfaces(){
  try{ifacesCache=await getJson('/api/interfaces')}catch{ifacesCache=[]}
}

function makeChips(box,fam,sugg){
  const list=box.querySelector('.chips-list'),
    input=box.querySelector('.chips-add input'),drop=box.querySelector('.chips-drop');
  const items=()=>[...list.children];
  const vals=()=>items().map(t=>t.dataset.v);
  const sync=()=>{
    const seen=new Set();
    items().forEach(x=>seen.has(x.dataset.v)?x.remove():seen.add(x.dataset.v));
    const its=items();
    its.forEach((t,i)=>{t.firstElementChild.textContent=i+1;t.querySelector('.chips-up').hidden=i===0;t.querySelector('.chips-down').hidden=i===its.length-1});
  };
  const item=v=>{
    const t=document.createElement('div');
    t.className='chips-item';t.dataset.v=v;
    const n=document.createElement('span');n.className='chips-num';
    const tx=document.createElement('span');tx.className='chips-txt';tx.textContent=v;
    const edit=document.createElement('input');edit.className='chips-edit';edit.value=v;edit.spellcheck=false;
    const ops=document.createElement('span');ops.className='chips-ops';
    const up=document.createElement('button');up.type='button';up.className='chips-btn chips-up';up.textContent='↑';up.title='上移';
    const down=document.createElement('button');down.type='button';down.className='chips-btn chips-down';down.textContent='↓';down.title='下移';
    const del=document.createElement('button');del.type='button';del.className='chips-btn';del.textContent='×';del.title='删除';
    const endEdit=()=>{
      if(!t.classList.contains('editing'))return;
      t.classList.remove('editing');
      const v=edit.value.trim();
      if(v){t.dataset.v=v;tx.textContent=edit.value=v}
      else t.remove();
      sync();
    };
    tx.addEventListener('click',()=>{t.classList.add('editing');edit.focus();edit.select()});
    edit.addEventListener('blur',endEdit);
    edit.addEventListener('keydown',e=>{
      if(e.key==='Enter'){e.preventDefault();endEdit();input.focus()}
      else if(e.key==='Escape'){edit.value=t.dataset.v;endEdit()}
    });
    up.addEventListener('click',()=>{t.previousElementSibling?.before(t);sync()});
    down.addEventListener('click',()=>{t.nextElementSibling?.after(t);sync()});
    del.addEventListener('click',()=>{t.remove();sync()});
    ops.append(up,down,del);
    t.append(n,tx,edit,ops);
    return t;
  };
  const add=v=>{
    v=String(v??'').trim();
    if(v){list.appendChild(item(v));sync()}
  };
  const commit=()=>{add(input.value);input.value=''};
  const show=()=>{
    const q=input.value.trim().toLowerCase();
    const out=[];
    if(sugg==='iface'){
      for(const x of ifacesCache){
        if(fam&&!x[fam])continue;
        out.push({v:x.name,l:`${x.name}（${fam?x[fam]:(x.v4||x.v6)}）`});
      }
      for(const p of['eth*','wlan*','usb*'])out.push({v:p,l:p});
    }else out.push(...sugg.map(u=>({v:u,l:u})));
    drop.innerHTML='';
    for(const o of out.filter(o=>o.v.toLowerCase().includes(q)&&!vals().includes(o.v)).slice(0,20)){
      const d=document.createElement('div');
      d.dataset.v=o.v;
      d.textContent=o.l;
      drop.appendChild(d);
    }
    drop.hidden=!drop.children.length;
  };
  drop.addEventListener('click',e=>{
    const d=e.target.closest('[data-v]');
    if(d){add(d.dataset.v);input.value='';show()}
  });
  input.addEventListener('input',()=>show());
  input.addEventListener('keydown',e=>{
    if(e.key==='Enter'){e.preventDefault();commit();show()}
    else if(e.key==='Backspace'&&!input.value){list.lastElementChild?.remove();sync();show()}
    else if(e.key==='Escape'||e.key==='Tab')drop.hidden=true;
  });
  input.addEventListener('focus',show);
  Object.defineProperty(box,'value',{
    get:()=>[...vals(),input.value.trim()].filter(Boolean),
    set:v=>{list.replaceChildren();(Array.isArray(v)?v:[v]).forEach(add);input.value=''}
  });
}
function fillTtl(sel,val){
  sel.innerHTML='';
  for(const[v,k]of TTL_OPTS)addOpt(sel,String(v),t_(k));
  ensureOpt(sel,String(val),val+' s');
  sel.value=String(val);
}
function srcValueBox(fam,type){
  if(type==='cmd'){const i=document.createElement('input');i.placeholder=t_('src.cmdPh');return i}
  const box=document.createElement('div');
  box.className='chips';
  box.innerHTML='<div class="chips-list"></div><div class="chips-add"><input></div><div class="chips-drop" hidden></div>';
  box.querySelector('input').placeholder=t_(type==='url'?'src.urlPh':'src.ifPh');
  makeChips(box,type==='netInterface'?fam:null,type==='netInterface'?'iface':(fam==='v4'?URLS_V4:URLS_V6));
  return box;
}

function makeSrcBlock(list,type,val){
  const row=document.createElement('div');
  row.className='src-grp';
  row.innerHTML='<div class="field src-head"><span class="label"><span data-i18n="ed.source">来源</span><span class="src-num"></span></span><div class="seg"></div><span class="src-ops"></span></div>';
  const fam=list.dataset.fam,seg=row.querySelector('.seg'),ops=row.querySelector('.src-ops');
  const wrap=document.createElement('div');
  wrap.className='field-col';
  const vals={};
  let box=srcValueBox(fam,type);
  wrap.appendChild(box);
  row.appendChild(wrap);
  for(const t of['netInterface','cmd','url']){
    const b=document.createElement('button');
    b.type='button';b.dataset.v=t;b.dataset.i18n=SRC_KEY[t];b.textContent=t_(SRC_KEY[t]);
    b.addEventListener('click',()=>{
      if(getSegEl(seg)===t)return;
      vals[getSegEl(seg)]=box.value;
      setSegEl(seg,t);
      box.replaceWith(box=srcValueBox(fam,t));
      if(vals[t]!==undefined)box.value=vals[t];
    });
    seg.appendChild(b);
  }
  setSegEl(seg,type);
  const mk=(txt,cls,fn)=>{const b=document.createElement('button');b.type='button';b.className='chips-btn '+cls;b.textContent=txt;b.addEventListener('click',()=>{fn();syncBlocks(list)});ops.appendChild(b)};
  mk('↑','chips-up',()=>row.previousElementSibling?.before(row));
  mk('↓','chips-down',()=>row.nextElementSibling?.after(row));
  mk('×','chips-del',()=>row.remove());
  row.get=()=>{const v=box.value;return makeSrc(getSegEl(seg),typeof v==='string'?v.trim():v)};
  if(val!==undefined&&!srcBlank(val))box.value=val;
  return row;
}

const collectSources=list=>[...list.children].map(r=>r.get()).filter(s=>!srcBlank(srcVals(s)));
const paintSources=(list,srcs)=>{
  list.replaceChildren(...(srcs.length?srcs:[defaultSrc(list.dataset.fam)]).map(s=>makeSrcBlock(list,s.type,srcVals(s))));
  syncBlocks(list);
};
function paintMode(){
  const poll=getSeg('ed-mode')==='poll';
  $('ed-interval-row').hidden=!poll;
  $('ed-watch-row').hidden=poll;
  $('ed-mode-hint').textContent=t_(poll?'mode.hint.poll':'mode.hint.listen');
}

function newEntry(){
  return {
    name:'',enabled:true,mode:'listen',interval:300,watch:[],zone:'',sub_domains:'@',ttl:0,
    ipv4:{enabled:false,sources:[]},
    ipv6:{enabled:false,sources:[]},
    provider:{type:'aliyun',access_key_id:'',access_key_secret:''},
  };
}

async function openEditor(i){
  edIdx=i;
  ed=i<0?newEntry():JSON.parse(JSON.stringify(cfg.entries[i]));
  await loadIfaces();
  $('ed-title').textContent=i<0?t_('ed.new'):t_('ed.edit');
  $('ed-del').hidden=i<0;
  $('ed-name').value=ed.name;
  $('ed-mode-listen').hidden=!monitorOk;
  if(ed.mode==='listen'&&!monitorOk)ed.mode='poll';
  setSeg('ed-mode',ed.mode||'poll');
  $('ed-interval').value=ed.interval||300;
  $('ed-watch').value=ed.watch||'';
  paintMode();
  fillTtl($('ed-ttl'),ed.ttl||0);
  $('ed-zone').value=ed.zone;
  $('ed-subs').value=ed.sub_domains;
  FAMS.forEach(([k,f])=>{
    const fam=ed[f]||(ed[f]={enabled:false,sources:[]});
    setToggle($('ed-'+k+'-en'),fam.enabled);
    paintSources($('ed-'+k+'-src'),fam.sources);
  });
  setSeg('ed-pv-type',ed.provider.type);
  paintProvider();
  $('ed-cf-token').value=ed.provider.token||'';
  setToggle($('ed-cf-proxied'),ed.provider.proxied);
  const ak=PV_AK[ed.provider.type];
  if(ak){
    $('ed-pv-ak').value=ed.provider[ak.k[0]]||'';
    $('ed-pv-sk').value=ak.k[1]?ed.provider[ak.k[1]]||'':'';
  }
  $('ed-cb-url').value=ed.provider.url||'';
  $('ed-cb-body').value=ed.provider.body||'';
  $('page-edit').classList.add('show');
}

const PV_AK={
  aliyun:{l:['AccessKey ID','AccessKey Secret'],k:['access_key_id','access_key_secret'],s:[false,true]},
  aliesa:{l:['AccessKey ID','AccessKey Secret'],k:['access_key_id','access_key_secret'],s:[false,true]},
  tencent:{l:['SecretId','SecretKey'],k:['secret_id','secret_key'],s:[false,true]},
  dnspod:{l:['ID','Token'],k:['id','token'],s:[false,true]},
  huawei:{l:['Access Key ID','Secret Access Key'],k:['access_key_id','secret_key'],s:[false,true]},
  baidu:{l:['Access Key ID','Secret Access Key'],k:['access_key_id','secret_key'],s:[false,true]},
  volcengine:{l:['Access Key ID','Secret Access Key'],k:['access_key_id','secret_key'],s:[false,true]},
  porkbun:{l:['API Key','Secret API Key'],k:['apikey','secretapikey'],s:[true,true]},
  godaddy:{l:['Key','Secret'],k:['key','secret'],s:[false,true]},
  namecheap:{l:['Dynamic DNS Password'],k:['password'],s:[true]},
};

function paintProvider(){
  const pv=getSeg('ed-pv-type');
  $('ed-pv-cf').hidden=pv!=='cloudflare';
  $('ed-pv-cb').hidden=pv!=='callback';
  const m=PV_AK[pv];
  $('ed-pv-keys').hidden=!m;
  if(m){
    $('ed-pv-ak-label').textContent=m.l[0];
    $('ed-pv-ak').placeholder=m.l[0];
    $('ed-pv-ak').type=m.s[0]?'password':'text';
    $('ed-pv-sk-row').hidden=m.k.length<2;
    if(m.k.length>1){
      $('ed-pv-sk-label').textContent=m.l[1];
      $('ed-pv-sk').placeholder=m.l[1];
      $('ed-pv-sk').type=m.s[1]?'password':'text';
    }
  }
}

function collectEntry(){
  const e={
    name:$('ed-name').value.trim(),
    enabled:edIdx<0?true:cfg.entries[edIdx].enabled,
    mode:getSeg('ed-mode')||'poll',
    interval:Number($('ed-interval').value)||300,
    watch:getSeg('ed-mode')==='listen'?$('ed-watch').value:[],
    zone:$('ed-zone').value.trim(),
    sub_domains:$('ed-subs').value.trim()||'@',
    ttl:Number($('ed-ttl').value)||0,
  };
  FAMS.forEach(([k,f])=>{
    e[f]={enabled:getToggle($('ed-'+k+'-en')),sources:collectSources($('ed-'+k+'-src'))};
  });
  const pv=getSeg('ed-pv-type');
  if(pv==='cloudflare')
    e.provider={type:'cloudflare',token:$('ed-cf-token').value.trim(),proxied:getToggle($('ed-cf-proxied'))};
  else if(pv==='callback')
    e.provider={type:'callback',url:$('ed-cb-url').value.trim(),body:$('ed-cb-body').value.trim()};
  else{
    const m=PV_AK[pv];
    e.provider={type:pv,[m.k[0]]:$('ed-pv-ak').value.trim(),...(m.k[1]?{[m.k[1]]:$('ed-pv-sk').value.trim()}:{})};
  }
  return e;
}

async function saveEntry(){
  const e=collectEntry();
  const next=JSON.parse(JSON.stringify(cfg));
  if(edIdx<0)next.entries.push(e);
  else next.entries[edIdx]=e;
  try{
    cfg=await apiOk('POST','/api/config',next);
    renderTasks();
    $('page-edit').classList.remove('show');
    showToast(t_('toast.saved'));
    infoPoll.resume();
  }catch(err){fail(err)}
}

function delEntry(i){
  confirmDialog(t_('del.title'),t_('del.msg'),async()=>{
    const next=JSON.parse(JSON.stringify(cfg));
    next.entries.splice(i,1);
    try{
      cfg=await apiOk('POST','/api/config',next);
      renderTasks();
      $('page-edit').classList.remove('show');
      showToast(t_('toast.deleted'));
      infoPoll.resume();
    }catch(e){fail(e)}
  });
}

function confirmDialog(title,msg,cb){
  $('modal-confirm-title').textContent=title;
  $('modal-confirm-msg').textContent=msg;
  confirmCb=cb;
  openModal('modal-confirm');
}

async function doChangePw(){
  if($('pw-new').value.length<8)return showToast(t_('login.tooShort'));
  if($('pw-new').value!==$('pw-new2').value)return showToast(t_('login.mismatch'));
  try{
    await apiOk('POST','/api/password',{old:$('pw-old').value,new:$('pw-new').value});
    closeModal('modal-pw');
    $('pw-old').value=$('pw-new').value=$('pw-new2').value='';
    showToast(t_('pw.ok'));
    setTimeout(doLogout,800);
  }catch(e){fail(e)}
}

function switchTab(name){
  ['status','tasks','settings'].forEach(x=>$('tab-'+x).hidden=x!==name);
  $('tabbar').querySelectorAll('.tab').forEach(b=>b.classList.toggle('active',b.dataset.tab===name));
}

function bindEvents(){
  $('tabbar').querySelectorAll('.tab').forEach(b=>b.addEventListener('click',()=>switchTab(b.dataset.tab)));
  $('login-pass').addEventListener('keydown',onEnter(doLogin));
  $('login-pass2').addEventListener('keydown',onEnter(doLogin));
  $('login-btn').addEventListener('click',doLogin);
  $('lg-lang').addEventListener('change',e=>{langDirty=true;setLang(e.target.value)});
  $('se-lang').addEventListener('change',e=>{langDirty=true;setLang(e.target.value)});
  $('se-logout').addEventListener('click',doLogout);
  async function saveSettings(){
    try{
      const next=JSON.parse(JSON.stringify(cfg));
      next.port=parseInt($('se-port').value)||0;
      next.log_cap=parseInt($('se-logcap').value)||0;
      next.token_ttl=(parseInt($('se-ttl').value)||0)*60;
      next.not_allow_wan=getToggle($('se-lan'));
      await apiOk('POST','/api/config',next);
      if(next.port!==cfg.port)return portJump(next.port);
      await reload();
      showToast(t_('se.saved'));
    }catch(e){fail(e)}
  }
  $('se-save').addEventListener('click',saveSettings);
  $('log-save').addEventListener('click',saveSettings);
  $('se-cancel').addEventListener('click',()=>{$('se-port').value=cfg.port;$('se-ttl').value=Math.round(cfg.token_ttl/60);setToggle($('se-lan'),cfg.not_allow_wan);seSync()});
  $('log-cancel').addEventListener('click',()=>{$('se-logcap').value=cfg.log_cap;seSync()});
  $('se-port').addEventListener('input',seSync);
  $('se-ttl').addEventListener('input',seSync);
  $('se-logcap').addEventListener('input',seSync);
  $('se-lan').addEventListener('click',function(){this.classList.toggle('on');seSync()});
  $('se-pwd').addEventListener('click',()=>openModal('modal-pw'));
  $('se-title').addEventListener('click',()=>{
    $('se-title-input').value=siteTitle;
    openModal('modal-title');
  });
  $('se-title-ok').addEventListener('click',saveTitle);
  $('se-about').addEventListener('click',()=>$('page-about').classList.add('show'));
  $('about-back').addEventListener('click',()=>$('page-about').classList.remove('show'));
  $('st-donate').addEventListener('click',()=>$('page-donate').classList.add('show'));
  $('se-donate').addEventListener('click',()=>$('page-donate').classList.add('show'));
  $('donate-back').addEventListener('click',()=>$('page-donate').classList.remove('show'));
  $('donate-ali').addEventListener('click',()=>location.href='https://qr.alipay.com/tsx183072iwa3igjxm5fjb6');
  $('st-run').addEventListener('click',async()=>{
    try{await apiOk('POST','/api/run');showToast(t_('toast.kicked'))}
    catch(e){fail(e)}
  });
  $('st-clear').addEventListener('click',async()=>{
    try{
      await apiOk('POST','/api/logs/clear');
      renderStatus(await getJson('/api/status'));
      showToast(t_('st.cleared'));
    }catch(e){fail(e)}
  });
  $('tk-add').addEventListener('click',()=>openEditor(-1));
  $('tk-list').addEventListener('click',e=>{
    const b=e.target.closest('button');
    if(!b)return;
    if(b.dataset.edit!==undefined)openEditor(Number(b.dataset.edit));
    else if(b.dataset.tg!==undefined)toggleEntry(Number(b.dataset.tg));
    else if(b.dataset.del!==undefined)delEntry(Number(b.dataset.del));
  });
  $('pw-ok').addEventListener('click',doChangePw);
  $('modal-confirm-ok').addEventListener('click',()=>{
    closeModal('modal-confirm');
    if(confirmCb){const cb=confirmCb;confirmCb=null;cb()}
  });
  $('ed-back').addEventListener('click',()=>$('page-edit').classList.remove('show'));
  $('ed-save').addEventListener('click',saveEntry);
  $('ed-del').addEventListener('click',()=>delEntry(edIdx));
  $('ed-cf-proxied').addEventListener('click',function(){this.classList.toggle('on')});
  for(const id of['ed-v4-en','ed-v6-en'])$(id).addEventListener('click',function(){this.classList.toggle('on')});
  FAMS.forEach(([k])=>{
    const list=$('ed-'+k+'-src');
    const b=document.createElement('button');
    b.type='button';b.className='src-add-btn';
    b.innerHTML='<svg viewBox="0 0 24 24"><path d="M12 5v14M5 12h14"/></svg><span data-i18n="src.add"></span>';
    b.querySelector('span').textContent=t_('src.add');
    b.addEventListener('click',()=>{list.appendChild(makeSrcBlock(list,'netInterface'));syncBlocks(list)});
    list.nextElementSibling.appendChild(b);
  });
  $('ed-mode').querySelectorAll('button').forEach(b=>b.addEventListener('click',()=>{
    if(getSeg('ed-mode')===b.dataset.v)return;
    setSeg('ed-mode',b.dataset.v);
    paintMode();
  }));
  $('ed-pv-type').querySelectorAll('button').forEach(b=>b.addEventListener('click',()=>{
    if(getSeg('ed-pv-type')===b.dataset.v)return;
    setSeg('ed-pv-type',b.dataset.v);
    paintProvider();
  }));
  document.addEventListener('click',e=>{
    const bg=e.target.closest('.modal-bg');
    if(!bg)return;
    if(e.target===bg||e.target.closest('[data-close]'))closeModal(bg.id);
  });
  document.addEventListener('pointerdown',e=>{
    document.querySelectorAll('.chips-drop:not([hidden])').forEach(d=>{
      const box=d.closest('.chips');
      if(!d.contains(e.target)&&e.target!==box.querySelector(':scope > .chips-add > input'))d.hidden=true;
    });
  });
  document.addEventListener('keydown',e=>{
    if(e.key!=='Escape')return;
    const bg=document.querySelector('.modal-bg:not([hidden])');
    if(bg)closeModal(bg.id);
  });
  document.addEventListener('visibilitychange',()=>{
    if(document.hidden)infoPoll.stop();
    else if(token)infoPoll.resume();
  });
  window.addEventListener('online',()=>token&&infoPoll.resume());
}

bindEvents();
makeChips($('ed-watch'),null,'iface');
fillLangSelects();
applyLang();
getJson('/api/site').then(s=>{siteTitle=s.title||'DDNS-RS';applyTitle();if(s.lang&&!langDirty)setLang(s.lang)}).catch(()=>{});
if(token){
  reload().then(()=>{show('app');switchTab('status');infoPoll.resume()}).catch(e=>e instanceof AuthError?showLogin():showToast(e.message));
}else showLogin();
