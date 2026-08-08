export type Plan={code:string;name:string;priceKopecks:number;deviceLimit:number;quotaBytes:number;speedBps:number;throttleBps:number;p2pAllowed:boolean;automaticLocation:boolean}
export type NodeInfo={id:string;domain:string;status:string;capacityMbps:number;loadRatio:number;controllerRttMs?:number;lastHeartbeatAt?:string}

function csrf(){return document.cookie.split('; ').find(v=>v.startsWith('rvpn_csrf='))?.split('=')[1]??''}
export async function api<T>(path:string,init:RequestInit={}):Promise<T>{const method=init.method??'GET';const response=await fetch('/api/v1'+path,{...init,headers:{'Accept':'application/json',...(method!=='GET'?{'Content-Type':'application/json','X-CSRF-Token':csrf()}:{}),...init.headers}});if(!response.ok){const problem=await response.json().catch(()=>({title:'Ошибка запроса'}));throw new Error(problem.detail||problem.title||'Ошибка запроса')}return response.status===204?undefined as T:response.json()}
export const formatBytes=(value:number)=>new Intl.NumberFormat('ru-RU',{style:'unit',unit:value>=1e12?'terabyte':'gigabyte',unitDisplay:'short',maximumFractionDigits:1}).format(value/(value>=1e12?1e12:1e9))
export const formatMoney=(kopecks:number)=>new Intl.NumberFormat('ru-RU',{style:'currency',currency:'RUB',maximumFractionDigits:0}).format(kopecks/100)
