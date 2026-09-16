export const runtime = 'edge';

type Status='pass'|'warning'|'danger'|'info';
type Severity='critical'|'high'|'medium'|'low'|'info';
type Finding={id:string;category:string;title:string;status:Status;severity:Severity;message:string;evidence?:string;recommendation?:string};
type PortResult={port:number;service:string;state:'open'|'closed';protocol:'http'|'https';status?:number;latency:number};
type DnsAnswer={name:string;type:number;data:string;TTL:number};
type DnsResponse={Status:number;AD?:boolean;Answer?:DnsAnswer[]};

const ALLOWED_ROOT='alperensenel.com';
const PORTS=[{port:80,service:'HTTP',protocol:'http'},{port:443,service:'HTTPS',protocol:'https'},{port:3000,service:'Dev server',protocol:'http'},{port:3001,service:'Dev server',protocol:'http'},{port:5000,service:'App server',protocol:'http'},{port:8000,service:'Web server',protocol:'http'},{port:8080,service:'HTTP alternatif',protocol:'http'},{port:8443,service:'HTTPS alternatif',protocol:'https'},{port:8888,service:'Web panel',protocol:'http'}] as const;
const SENSITIVE=[['/.env','Ortam değişkeni dosyası'],['/.env.local','Yerel ortam dosyası'],['/.git/HEAD','Git depo bilgisi'],['/wp-config.php.bak','WordPress yapılandırma yedeği'],['/config.php.bak','Yapılandırma yedeği'],['/backup.zip','Yedek arşivi'],['/server-status','Sunucu durum sayfası'],['/package.json','Paket manifesti']] as const;
const json=(data:unknown,status=200)=>Response.json(data,{status,headers:{'Cache-Control':'no-store','Content-Security-Policy':"default-src 'none'; frame-ancestors 'none'",'X-Content-Type-Options':'nosniff'}});
const finding=(id:string,category:string,title:string,status:Status,severity:Severity,message:string,evidence?:string,recommendation?:string):Finding=>({id,category,title,status,severity,message,evidence,recommendation});

function normalizeTarget(value:string){
 const clean=value.trim().toLowerCase().replace(/^https?:\/\//,'').split('/')[0].replace(/\.$/,'');
 if(!/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(clean))throw new Error('Geçerli bir alan adı gir.');
 if(clean!==ALLOWED_ROOT&&!clean.endsWith(`.${ALLOWED_ROOT}`))throw new Error(`Yalnızca ${ALLOWED_ROOT} ve alt alan adları taranabilir.`);
 return clean;
}

async function fetchTimed(url:string,init:RequestInit={},timeout=5500){
 const controller=new AbortController();const timer=setTimeout(()=>controller.abort('timeout'),timeout);const started=Date.now();
 try{const response=await fetch(url,{...init,signal:controller.signal,redirect:init.redirect??'manual',headers:{'User-Agent':'WebTest-Security-Audit/1.0',...(init.headers||{})}});return{response,latency:Date.now()-started}}finally{clearTimeout(timer)}
}

async function readLimited(response:Response,limit=262144){
 if(!response.body)return'';const reader=response.body.getReader();const decoder=new TextDecoder();let text='',size=0;
 try{while(size<limit){const{done,value}=await reader.read();if(done)break;size+=value.byteLength;text+=decoder.decode(value,{stream:true});if(size>=limit)break}}finally{await reader.cancel().catch(()=>undefined)}
 return text.slice(0,limit);
}

async function probePort(host:string,item:typeof PORTS[number]):Promise<PortResult>{
 const suffix=(item.port===80&&item.protocol==='http')||(item.port===443&&item.protocol==='https')?'':`:${item.port}`;const started=Date.now();
 try{const{response,latency}=await fetchTimed(`${item.protocol}://${host}${suffix}/`,{method:'HEAD'},3800);return{...item,state:'open',status:response.status,latency}}catch{return{...item,state:'closed',latency:Date.now()-started}}
}

async function dnsQuery(name:string,type:string){
 try{const{response}=await fetchTimed(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`,{headers:{Accept:'application/dns-json'}},4500);if(!response.ok)return null;return await response.json<DnsResponse>()}catch{return null}
}

function headerCheck(headers:Headers,name:string,title:string,category:string,severity:Severity,recommendation:string,validate?:(v:string)=>boolean){
 const value=headers.get(name);if(value&&(!validate||validate(value)))return finding(`header-${name}`,category,title,'pass','info',`${name} etkin.`,value);
 return finding(`header-${name}`,category,title,'warning',severity,`${name} eksik veya yetersiz.`,value||'Başlık bulunamadı',recommendation);
}

async function scan(host:string){
 const started=Date.now();const findings:Finding[]=[];
 const ports=await Promise.all(PORTS.map(port=>probePort(host,port)));
 const unusual=ports.filter(p=>p.state==='open'&&![80,443].includes(p.port));
 findings.push(unusual.length?finding('ports-extra','Web servisleri','Standart dışı web servisleri erişilebilir','warning','medium',`${unusual.map(p=>p.port).join(', ')} portları HTTP(S) yanıtı verdi.`,unusual.map(p=>`${p.port}/${p.protocol.toUpperCase()} → HTTP ${p.status}`).join(' · '),'Gerekli olmayan servisleri kapat; gerekli olanları kimlik doğrulama ve ağ kısıtlarıyla koru.'):finding('ports-extra','Web servisleri','Gereksiz web servisi görünmüyor','pass','info','Kontrol edilen standart dışı web portları yanıt vermedi.'));
 findings.push(ports.some(p=>p.port===443&&p.state==='open')?finding('https-port','Web servisleri','HTTPS erişilebilir','pass','info','443 numaralı HTTPS servisi yanıt veriyor.'):finding('https-port','Web servisleri','HTTPS servisi erişilemiyor','danger','critical','443 numaralı porttan HTTPS yanıtı alınamadı.',undefined,'HTTPS hizmetini ve DNS yönlendirmesini doğrula.'));

 let main:Response|null=null,html='';
 try{const result=await fetchTimed(`https://${host}/`,{headers:{Accept:'text/html,application/xhtml+xml'}},8000);main=result.response;html=await readLimited(main.clone());findings.push(finding('https-response','HTTP','HTTPS ana sayfa yanıtı','pass','info',`Sunucu HTTP ${main.status} ile ${result.latency} ms içinde yanıt verdi.`,`HTTP ${main.status} · ${result.latency} ms`))}catch{findings.push(finding('https-response','HTTP','HTTPS ana sayfa erişilemiyor','danger','critical','Ana sayfaya güvenli bağlantı kurulamadı.',undefined,'DNS, SSL sertifikası ve origin erişimini kontrol et.'))}

 if(main){
  const h=main.headers;
  findings.push(headerCheck(h,'strict-transport-security','HSTS politikası','Güvenlik başlıkları','high','Strict-Transport-Security: max-age=31536000; includeSubDomains kullan.',v=>/max-age=(?:[3-9]\d{7,}|[1-9]\d{8,})/i.test(v)));
  findings.push(headerCheck(h,'content-security-policy','Content Security Policy','Güvenlik başlıkları','high','Kaynakları allowlist eden bir CSP tanımla.',v=>/default-src|script-src/i.test(v)));
  findings.push(headerCheck(h,'x-content-type-options','MIME sniffing koruması','Güvenlik başlıkları','medium','X-Content-Type-Options: nosniff ekle.',v=>v.toLowerCase()==='nosniff'));
  const csp=h.get('content-security-policy')||'';const xfo=h.get('x-frame-options');findings.push(xfo||/frame-ancestors/i.test(csp)?finding('frame-protection','Güvenlik başlıkları','Clickjacking koruması','pass','info','Çerçeveleme kısıtlaması mevcut.',xfo||csp.match(/frame-ancestors[^;]*/i)?.[0]):finding('frame-protection','Güvenlik başlıkları','Clickjacking koruması eksik','warning','high','X-Frame-Options veya CSP frame-ancestors bulunamadı.',undefined,"CSP içinde frame-ancestors 'none' veya uygun allowlist kullan."));
  findings.push(headerCheck(h,'referrer-policy','Referrer Policy','Güvenlik başlıkları','low','Referrer-Policy: strict-origin-when-cross-origin ekle.'));
  findings.push(headerCheck(h,'permissions-policy','Permissions Policy','Güvenlik başlıkları','low','Kullanılmayan kamera, mikrofon ve konum yetkilerini Permissions-Policy ile kapat.'));
  findings.push(headerCheck(h,'cross-origin-opener-policy','Cross-Origin Opener Policy','Güvenlik başlıkları','low','Cross-Origin-Opener-Policy: same-origin değerlendir.'));
  const server=[h.get('server'),h.get('x-powered-by')].filter(Boolean).join(' · ');findings.push(server?finding('tech-leak','Bilgi sızıntısı','Sunucu teknolojisi açıklanıyor','warning','low','Yanıt başlıkları altyapı bilgisi sızdırıyor.',server,'Server ve X-Powered-By başlıklarını kaldır veya genelleştir.'):finding('tech-leak','Bilgi sızıntısı','Teknoloji başlığı sızıntısı yok','pass','info','Server ve X-Powered-By başlıklarında belirgin teknoloji bilgisi bulunmadı.'));
  const cookies=h.get('set-cookie');if(cookies){const missing=[];if(!/;\s*secure/i.test(cookies))missing.push('Secure');if(!/;\s*httponly/i.test(cookies))missing.push('HttpOnly');if(!/;\s*samesite=/i.test(cookies))missing.push('SameSite');findings.push(missing.length?finding('cookies','Oturum','Çerez güvenlik bayrakları eksik','warning','high',`Eksik bayraklar: ${missing.join(', ')}`,'Set-Cookie değeri gizlilik için raporda gösterilmedi.','Oturum çerezlerinde Secure, HttpOnly ve uygun SameSite politikasını birlikte kullan.'):finding('cookies','Oturum','Çerez bayrakları güvenli','pass','info','Gözlenen çerezler temel güvenlik bayraklarını içeriyor.'))}else findings.push(finding('cookies','Oturum','Yanıtta çerez yok','pass','info','Ana sayfa yanıtında Set-Cookie gözlenmedi.'));
  const mixed=(html.match(/(?:src|href)=["']http:\/\//gi)||[]).length;findings.push(mixed?finding('mixed-content','İçerik','Karma içerik bağlantıları bulundu','warning','medium',`${mixed} adet HTTP kaynağı HTTPS sayfada referans ediliyor.`,undefined,'Tüm kaynak URL’lerini HTTPS yap.'):finding('mixed-content','İçerik','Karma içerik görünmüyor','pass','info','İncelenen HTML bölümünde HTTP kaynak bağlantısı bulunmadı.'));
  if(/<form\b/i.test(html)){const insecure=/<form[^>]+action=["']http:\/\//i.test(html);findings.push(insecure?finding('form-action','Formlar','Güvensiz form hedefi','danger','high','Bir form veriyi HTTP adresine gönderiyor.',undefined,'Form action adresini HTTPS yap.'):finding('form-action','Formlar','Form hedefleri güvenli görünüyor','pass','info','İncelenen formlarda HTTP action bulunmadı.'))}
 }

 try{const{response}=await fetchTimed(`http://${host}/`,{},4500);const location=response.headers.get('location')||'';findings.push(response.status>=300&&response.status<400&&location.startsWith('https://')?finding('https-redirect','HTTP','HTTP → HTTPS yönlendirmesi','pass','info','HTTP istekleri HTTPS’e yönlendiriliyor.',`HTTP ${response.status} → ${location}`):finding('https-redirect','HTTP','HTTPS yönlendirmesi eksik','warning','high','HTTP isteği doğrudan güvenli adrese yönlenmedi.',`HTTP ${response.status}${location?` → ${location}`:''}`,'Tüm HTTP trafiğini kalıcı olarak HTTPS’e yönlendir.'))}catch{findings.push(finding('https-redirect','HTTP','HTTP servisi kapalı','pass','info','HTTP portu yanıt vermedi; yalnızca HTTPS kullanılıyor olabilir.'))}

 if(main){try{const{response}=await fetchTimed(`https://${host}/`,{headers:{Origin:'https://attacker.invalid'}},4500);const acao=response.headers.get('access-control-allow-origin');const creds=response.headers.get('access-control-allow-credentials');findings.push(acao==='*'&&creds==='true'?finding('cors','CORS','Tehlikeli CORS yapılandırması','danger','critical','Her origin için kimlik bilgili erişim işareti gözlendi.',`ACAO: ${acao} · ACAC: ${creds}`,'İzin verilen origin’leri açık allowlist ile sınırla; wildcard ile credentials kullanma.'):acao==='*'?finding('cors','CORS','Geniş CORS politikası','warning','medium','Access-Control-Allow-Origin tüm origin’lere açık.','ACAO: *','Yalnızca gerçekten gereken origin’leri allowlist et.'):finding('cors','CORS','CORS politikası kısıtlı','pass','info','Rastgele origin için geniş erişim izni gözlenmedi.',acao?`ACAO: ${acao}`:'ACAO başlığı yok'))}catch{findings.push(finding('cors','CORS','CORS testi tamamlanamadı','info','info','Ek origin isteği yanıt vermedi.'))}}

 const baseline=html.replace(/\s+/g,' ').slice(0,800);
 const leaked:string[]=[];
 await Promise.all(SENSITIVE.map(async([path,label])=>{try{const{response}=await fetchTimed(`https://${host}${path}`,{headers:{Accept:'text/plain,*/*'}},3500);if(response.status!==200)return;const body=await readLimited(response,4096);const normalized=body.replace(/\s+/g,' ').slice(0,800);const generic=normalized&&baseline&&normalized===baseline;const signatures=path.includes('.env')?/\b[A-Z][A-Z0-9_]{2,}\s*=/:path.includes('.git')?/^ref:\s+refs\//:path.endsWith('.zip')?/^PK/:path.includes('package.json')?/"(?:dependencies|scripts|name)"/:/./;if(!generic&&signatures.test(body))leaked.push(`${label} (${path})`) }catch{}}));
 findings.push(leaked.length?finding('sensitive-files','Bilgi sızıntısı','Hassas dosyalar erişilebilir','danger','critical',`${leaked.length} şüpheli kaynak herkese açık yanıt verdi.`,leaked.join(' · '),'Dosyaları web kökünden kaldır, erişimi engelle ve sızmış olabilecek sırları değiştir.'):finding('sensitive-files','Bilgi sızıntısı','Hassas dosya sızıntısı görünmüyor','pass','info','Kontrol edilen yaygın hassas yollar gerçek dosya içeriği döndürmedi.'));

 try{const random=`webtest-${crypto.randomUUID()}.txt`;const{response}=await fetchTimed(`https://${host}/${random}`,{},3500);const body=await readLimited(response,16384);const verbose=/stack trace|traceback|exception|at\s+[\w$.]+\s*\([^)]*:\d+:\d+\)|sqlstate|fatal error/i.test(body);findings.push(verbose?finding('error-disclosure','Bilgi sızıntısı','Ayrıntılı hata bilgisi sızıyor','danger','high','Rastgele 404 isteği teknik hata ayrıntıları döndürdü.',undefined,'Üretimde ayrıntılı hata ve stack trace gösterimini kapat.'):response.status===200?finding('soft-404','HTTP','Soft 404 davranışı','warning','low','Var olmayan yol HTTP 200 döndürüyor.',`HTTP ${response.status}`,'Var olmayan kaynaklar için gerçek 404 durum kodu döndür.'):finding('error-disclosure','Bilgi sızıntısı','Hata sayfası ayrıntı sızdırmıyor','pass','info',`Var olmayan kaynak HTTP ${response.status} döndürdü.`))}catch{}

 const [a,aaaa,cname,txt,mx,dmarc]=await Promise.all([dnsQuery(host,'A'),dnsQuery(host,'AAAA'),dnsQuery(host,'CNAME'),dnsQuery(ALLOWED_ROOT,'TXT'),dnsQuery(ALLOWED_ROOT,'MX'),dnsQuery(`_dmarc.${ALLOWED_ROOT}`,'TXT')]);
 const answers=[...(a?.Answer||[]),...(aaaa?.Answer||[]),...(cname?.Answer||[])];findings.push(answers.length?finding('dns-resolution','DNS','DNS kayıtları çözümleniyor','pass','info',`${answers.length} A/AAAA/CNAME cevabı alındı.`,answers.slice(0,6).map(x=>x.data).join(' · ')):finding('dns-resolution','DNS','DNS çözümlemesi başarısız','danger','high','A, AAAA veya CNAME cevabı alınamadı.',undefined,'Yetkili DNS kayıtlarını kontrol et.'));
 findings.push(a?.AD||aaaa?.AD||cname?.AD?finding('dnssec','DNS','DNSSEC doğrulaması etkin','pass','info','DNS yanıtı doğrulanmış veri işareti taşıyor.'):finding('dnssec','DNS','DNSSEC doğrulaması görünmüyor','warning','medium','DNS yanıtlarında AD işareti gözlenmedi.',undefined,'Alan adı sağlayıcında DNSSEC’i etkinleştir ve DS kaydını doğrula.'));
 const spf=(txt?.Answer||[]).some(x=>/v=spf1/i.test(x.data));const hasMx=(mx?.Answer||[]).length>0;findings.push(!hasMx?finding('spf','E-posta','E-posta servisi tanımlı değil','info','info','MX kaydı bulunmadı; alan adı e-posta göndermiyorsa bu normaldir.'):spf?finding('spf','E-posta','SPF kaydı mevcut','pass','info','Alan adında SPF politikası bulundu.'):finding('spf','E-posta','SPF kaydı eksik','warning','medium','MX kaydı var ancak SPF politikası bulunamadı.',undefined,'Yetkili e-posta gönderenlerini tanımlayan SPF TXT kaydı ekle.'));
 const dmarcValue=(dmarc?.Answer||[]).find(x=>/v=dmarc1/i.test(x.data))?.data;findings.push(!hasMx?finding('dmarc','E-posta','DMARC gerekli olmayabilir','info','info','MX kaydı olmadığı için e-posta sahteciliği kapsamı sınırlı.'):dmarcValue?finding('dmarc','E-posta','DMARC politikası mevcut','pass','info','DMARC kaydı bulundu.',dmarcValue):finding('dmarc','E-posta','DMARC kaydı eksik','warning','high','E-posta alanı için DMARC politikası bulunamadı.',undefined,`_dmarc.${ALLOWED_ROOT} altında DMARC TXT kaydı ekle.`));

 const weight:Record<Severity,number>={critical:25,high:14,medium:8,low:3,info:0};const penalty=findings.filter(f=>f.status==='danger'||f.status==='warning').reduce((n,f)=>n+weight[f.severity],0);const score=Math.max(0,100-penalty);
 const counts={critical:findings.filter(f=>f.severity==='critical'&&f.status==='danger').length,high:findings.filter(f=>f.severity==='high'&&(f.status==='danger'||f.status==='warning')).length,medium:findings.filter(f=>f.severity==='medium'&&(f.status==='danger'||f.status==='warning')).length,low:findings.filter(f=>f.severity==='low'&&(f.status==='danger'||f.status==='warning')).length,passed:findings.filter(f=>f.status==='pass').length};
 return{target:host,scannedAt:new Date().toISOString(),duration:Date.now()-started,score,counts,ports,findings,limitations:['Port kontrolü ham TCP taraması değil; HTTP(S) yanıtı verebilen yaygın web portlarını denetler.','Tarama pasiftir; parola denemesi, zafiyet istismarı, yoğun yük veya veri değiştirme uygulanmaz.']};
}

export async function POST(request:Request){
 try{const length=Number(request.headers.get('content-length')||0);if(length>2048)return json({error:'İstek çok büyük.'},413);const raw=await request.text();if(raw.length>2048)return json({error:'İstek çok büyük.'},413);const body:unknown=JSON.parse(raw);if(!body||typeof body!=='object'||!('target'in body)||typeof body.target!=='string')return json({error:'Hedef alan adı gerekli.'},400);const host=normalizeTarget(body.target);return json(await scan(host))}catch(error){const message=error instanceof Error?error.message:'Tarama tamamlanamadı.';console.error(JSON.stringify({message:'scan_failed',error:message}));return json({error:message},message.includes('Yalnızca')||message.includes('Geçerli')?400:500)}
}

export function GET(){return json({service:'WebTest Security Scanner',scope:[ALLOWED_ROOT,`*.${ALLOWED_ROOT}`],mode:'passive-authorized-only'})}
