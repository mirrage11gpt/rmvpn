const json=(body:unknown,status=200)=>Promise.resolve(new Response(JSON.stringify(body),{status,headers:{'Content-Type':'application/json'}}))

export function installPreviewMocks(){
  const original=window.fetch.bind(window)
  window.fetch=(input,init={})=>{
    const url=new URL(typeof input==='string'?input:input instanceof URL?input.href:input.url,location.origin)
    if(!url.pathname.startsWith('/api/v1'))return original(input,init)
    const path=url.pathname.slice('/api/v1'.length)
    if(path==='/me')return json({displayName:'Михаил',username:'mirragetag',balanceKopecks:74800,role:'owner',csrfToken:'preview',termsAccepted:true})
    if(path==='/subscription')return json({plan:'PLUS',status:'active',quotaBytes:600e9,usedBytes:184e9})
    if(path==='/devices')return json({items:[{id:'d1',slot:1,name:'iPhone 16 Pro',bound:true,lastSeenAt:'2026-08-09T11:42:00Z'},{id:'d2',slot:2,name:'MacBook',bound:false}]})
    if(path==='/admin/mfa')return json({enabled:true,verified:true})
    if(path==='/admin/overview')return json({users:1284,newUsers7d:93,activeSubscriptions:742,graceSubscriptions:12,devices:1198,boundDevices:1047,healthyNodes:9,activeAlerts:2})
    if(path==='/admin/statistics')return json({usageBytes30d:18.7e12,creditsKopecks30d:8425000,chargesKopecks30d:6913000,plans:[{plan:'TRIAL',users:410,usedBytes:2.8e12,quotaBytes:8.2e12},{plan:'LITE',users:358,usedBytes:9.1e12,quotaBytes:53.7e12},{plan:'PLUS',users:401,usedBytes:31.4e12,quotaBytes:240.6e12},{plan:'ULTRA',users:115,usedBytes:28.2e12,quotaBytes:230e12}],registrations:Array.from({length:14},(_,i)=>({day:`2026-08-${String(i+1).padStart(2,'0')}`,users:[4,9,6,12,8,15,11,7,16,19,12,21,17,23][i]}))})
    if(path==='/admin/users')return json({items:[{id:'u1',displayName:'мираж',username:'mirragetag',status:'active',createdAt:'2026-08-02T09:12:00Z',lastLoginAt:'2026-08-09T11:40:00Z',balanceKopecks:74800,plan:'PLUS',subscriptionStatus:'active',periodEndsAt:'2026-09-01T09:12:00Z',usedBytes:184e9,quotaBytes:600e9,devices:2,roles:'owner'},{id:'u2',displayName:'Алексей Воронцов',username:'avvnet',status:'active',createdAt:'2026-08-04T13:00:00Z',lastLoginAt:'2026-08-09T08:21:00Z',balanceKopecks:14900,plan:'LITE',subscriptionStatus:'active',usedBytes:48e9,quotaBytes:150e9,devices:1,roles:''},{id:'u3',displayName:'Мария',username:'',status:'blocked',createdAt:'2026-08-07T16:00:00Z',balanceKopecks:0,plan:'TRIAL',subscriptionStatus:'suspended',usedBytes:3e9,quotaBytes:20e9,devices:1,roles:''}]})
    if(path==='/admin/admins')return json({items:[{id:'u1',displayName:'мираж',username:'mirragetag',role:'owner',status:'active',mfaEnabled:true,lastLoginAt:'2026-08-09T11:40:00Z'},{id:'u4',displayName:'Служба поддержки',username:'rise_support',role:'support',status:'active',mfaEnabled:true,lastLoginAt:'2026-08-09T10:10:00Z'}]})
    if(path==='/admin/nodes')return json({items:[{id:'n1',domain:'f1.risevpn.space',status:'healthy',capacityMbps:1000,loadRatio:.34,controllerRttMs:41,lastHeartbeatAt:'2026-08-09T11:44:00Z'},{id:'n2',domain:'waw-1.risevpn.space',status:'degraded',capacityMbps:500,loadRatio:.81,controllerRttMs:62,lastHeartbeatAt:'2026-08-09T11:43:00Z'}]})
    if(path==='/admin/alerts')return json({items:[{id:'a1',severity:'critical',message:'Compliance feed не обновлялся более 6 часов',active:true,createdAt:'2026-08-09T06:00:00Z'}]})
    if(path==='/admin/audit')return json({items:[{id:'e1',action:'wallet.adjust',subjectType:'user',subjectId:'u2-4fa19bd3',reason:'Ручное пополнение',createdAt:'2026-08-09T11:20:00Z'}]})
    if(path==='/admin/ledger')return json({items:[{id:'l1',userId:'u2',displayName:'Алексей Воронцов',username:'avvnet',amountKopecks:14900,balanceAfterKopecks:14900,reason:'Ручное пополнение',createdAt:'2026-08-09T11:20:00Z'}]})
    return json({title:'Preview endpoint not found'},404)
  }
}
