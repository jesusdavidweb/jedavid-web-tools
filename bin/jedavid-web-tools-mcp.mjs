#!/usr/bin/env node
import { lookup } from 'node:dns/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
const VERSION = '0.2.0';
const MAX_HTML = 2_500_000;
const UA = `jedavid-web-tools/${VERSION} (+https://github.com/jesusdavidweb/jedavid-web-tools)`;

const objectSchema = (properties = {}, required = []) => ({ type: 'object', properties, required, additionalProperties: false });
const urlProp = { type: 'string', description: 'Public HTTP(S) URL or hostname.' };
const repoProp = { type: 'string', pattern: '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$', description: 'GitHub repository as owner/name.' };

const TOOLS = [
  ['accessibility_audit','Static accessibility audit','Inspect language, alt text, labels, headings, landmarks and basic document accessibility signals.',objectSchema({url:urlProp},['url'])],
  ['cloudflare_dns','Cloudflare DNS records','List DNS records for a zone using CLOUDFLARE_API_TOKEN.',objectSchema({domain:{type:'string'}},['domain'])],
  ['cloudflare_workers','Cloudflare Workers','List Worker scripts using CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID.',objectSchema()],
  ['cloudflare_zone','Cloudflare zone','Read Cloudflare zone metadata using CLOUDFLARE_API_TOKEN.',objectSchema({domain:{type:'string'}},['domain'])],
  ['docker_inspect','Docker inspect','Read docker inspect data for one local container.',objectSchema({container:{type:'string',pattern:'^[A-Za-z0-9_.-]+$'}},['container'])],
  ['docker_logs','Docker logs','Read a bounded tail of local container logs.',objectSchema({container:{type:'string',pattern:'^[A-Za-z0-9_.-]+$'},lines:{type:'integer',minimum:1,maximum:500,default:100}},['container'])],
  ['docker_ps','Docker containers','List local Docker containers and status.',objectSchema()],
  ['github_actions','GitHub Actions runs','Read recent GitHub Actions runs using optional GITHUB_TOKEN.',objectSchema({repo:repoProp,limit:{type:'integer',minimum:1,maximum:20,default:10}},['repo'])],
  ['github_repo','GitHub repository','Read repository metadata using optional GITHUB_TOKEN.',objectSchema({repo:repoProp},['repo'])],
  ['http_inspect','HTTP inspection','Inspect redirects, response status, headers, HTML size and response time.',objectSchema({url:urlProp},['url'])],
  ['page_compare','Compare pages','Compare two URLs across HTTP, performance, SEO and security signals.',objectSchema({before:urlProp,after:urlProp},['before','after'])],
  ['performance_assets','Asset inventory','Inspect same-origin scripts, stylesheets and images referenced by initial HTML.',objectSchema({url:urlProp,limit:{type:'integer',minimum:1,maximum:50,default:25}},['url'])],
  ['performance_audit','Performance audit','Audit document latency, HTML weight, resource pressure, image loading and caching signals.',objectSchema({url:urlProp},['url'])],
  ['robots_inspect','robots.txt inspection','Fetch and analyze robots.txt directives and sitemap declarations.',objectSchema({url:urlProp},['url'])],
  ['security_cookies','Cookie security','Inspect Set-Cookie attributes exposed by the initial response.',objectSchema({url:urlProp},['url'])],
  ['security_headers','Security headers','Audit browser-facing HTTP security headers and information disclosure.',objectSchema({url:urlProp},['url'])],
  ['seo_audit','Technical SEO audit','Audit title, description, canonical, headings, robots, hreflang, images and structured data.',objectSchema({url:urlProp},['url'])],
  ['seo_indexability','SEO indexability','Inspect HTTP status, robots directives, canonical and robots.txt for indexability risks.',objectSchema({url:urlProp},['url'])],
  ['seo_links','Link analysis','Analyze internal/external links, nofollow attributes and anchor quality.',objectSchema({url:urlProp},['url'])],
  ['seo_llm','LLM discoverability','Inspect llms.txt, robots directives for AI crawlers, semantic metadata and structured facts.',objectSchema({url:urlProp},['url'])],
  ['seo_schema','Structured data','Parse JSON-LD blocks and summarize schema.org types and parse errors.',objectSchema({url:urlProp},['url'])],
  ['site_audit','Full website audit','Run the broad read-only audit across performance, SEO, accessibility and security.',objectSchema({url:urlProp},['url'])],
  ['sitemap_inspect','Sitemap inspection','Fetch sitemap.xml and summarize URL or sitemap-index entries.',objectSchema({url:urlProp,limit:{type:'integer',minimum:1,maximum:200,default:100}},['url'])],
  ['stack_detect','Technology detection','Infer CDN, framework, CMS, analytics and server technologies from HTML and headers.',objectSchema({url:urlProp},['url'])],
  ['woocommerce_system_status','WooCommerce system status','Read configured WooCommerce system status via WC REST API credentials.',objectSchema()],
  ['woocommerce_webhooks','WooCommerce webhooks','List configured WooCommerce webhooks via WC REST API credentials.',objectSchema({limit:{type:'integer',minimum:1,maximum:100,default:20}})],
  ['wordpress_plugins','WordPress plugins','List plugins from the configured WordPress REST endpoint using application-password credentials.',objectSchema()],
  ['wordpress_rest_index','WordPress REST index','Inspect the configured WordPress REST API namespaces and routes.',objectSchema()]
].map(([name,title,description,inputSchema])=>({name,title,description,inputSchema,annotations:{readOnlyHint:true,destructiveHint:false,idempotentHint:true,openWorldHint:true}}));

function textResult(value) { return { content: [{ type: 'text', text: JSON.stringify(value, null, 2) }], structuredContent: value }; }
function errResult(error) { return { isError: true, content: [{ type:'text', text: error instanceof Error ? error.message : String(error) }] }; }
function trim(v){ return typeof v==='string' ? v.trim() : ''; }
function hostnameUrl(input){ return /^https?:\/\//i.test(input) ? input : `https://${input}`; }
function isPrivateIp(ip){
  const x=ip.toLowerCase();
  if(x==='::1'||x.startsWith('fc')||x.startsWith('fd')||x.startsWith('fe80:')) return true;
  if(x.startsWith('127.')||x.startsWith('10.')||x.startsWith('169.254.')||x.startsWith('0.')) return true;
  const m=x.match(/^172\.(\d+)\./); if(m&&+m[1]>=16&&+m[1]<=31) return true;
  if(x.startsWith('192.168.')) return true;
  return false;
}
async function assertPublic(url){
  if(!['http:','https:'].includes(url.protocol)) throw new Error('Only HTTP(S) URLs are supported.');
  if(['localhost','localhost.localdomain'].includes(url.hostname.toLowerCase())) throw new Error('Localhost is blocked.');
  const addresses=await lookup(url.hostname,{all:true});
  if(!addresses.length||addresses.some(a=>isPrivateIp(a.address))) throw new Error('Private/local network targets are blocked.');
}
async function safeFetch(input,{method='GET',headers={},timeoutMs=15000,maxRedirects=5}={}){
  let url=new URL(hostnameUrl(input));
  for(let i=0;i<=maxRedirects;i++){
    await assertPublic(url);
    const controller=new AbortController(); const timer=setTimeout(()=>controller.abort(),timeoutMs);
    const started=performance.now();
    let response;
    try{ response=await fetch(url,{method,redirect:'manual',signal:controller.signal,headers:{'user-agent':UA,...headers}}); }
    finally{ clearTimeout(timer); }
    const responseMs=Math.round(performance.now()-started);
    if([301,302,303,307,308].includes(response.status)&&response.headers.get('location')){
      if(i===maxRedirects) throw new Error('Too many redirects.');
      url=new URL(response.headers.get('location'),url); continue;
    }
    return {response,responseMs,url};
  }
  throw new Error('Unable to fetch URL.');
}
async function fetchText(input,options={}){
  const {response,responseMs,url}=await safeFetch(input,{...options,headers:{accept:'text/html,application/xhtml+xml,text/plain,application/xml;q=0.9,*/*;q=0.5',...(options.headers||{})}});
  const text=await response.text();
  if(Buffer.byteLength(text)>MAX_HTML) throw new Error(`Response exceeds ${MAX_HTML} bytes.`);
  return {response,responseMs,url,text};
}
function headersObj(h){ return Object.fromEntries([...h.entries()].sort(([a],[b])=>a.localeCompare(b))); }
function first(html,re,group=1){ const m=html.match(re); return m ? trim(m[group])||null : null; }
function count(html,re){ return [...html.matchAll(re)].length; }
function attrs(tag){ const out={}; for(const m of tag.matchAll(/([:\w-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/g)) out[m[1].toLowerCase()]=m[2]??m[3]??m[4]??''; return out; }
function tags(html,name){ return [...html.matchAll(new RegExp(`<${name}\\b[^>]*>`,'gi'))].map(m=>({tag:m[0],attrs:attrs(m[0])})); }
function pageModel(html,base){
  const title=first(html,/<title[^>]*>([\s\S]*?)<\/title>/i)?.replace(/<[^>]+>/g,' ').replace(/\s+/g,' ')||null;
  const metas=tags(html,'meta'); const links=tags(html,'link'); const imgs=tags(html,'img'); const scripts=tags(html,'script');
  const meta=(name)=>metas.find(x=>(x.attrs.name||'').toLowerCase()===name)?.attrs.content||null;
  const canonical=links.find(x=>(x.attrs.rel||'').toLowerCase().split(/\s+/).includes('canonical'))?.attrs.href||null;
  const lang=first(html,/<html\b[^>]*\blang\s*=\s*["']([^"']+)["']/i);
  const hrefs=[...html.matchAll(/<a\b[^>]*\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/gi)].map(m=>m[1]??m[2]??m[3]).filter(Boolean);
  return {title,description:meta('description'),robots:meta('robots'),canonical,lang,h1:count(html,/<h1\b/gi),h2:count(html,/<h2\b/gi),scripts:scripts.filter(x=>x.attrs.src).length,stylesheets:links.filter(x=>(x.attrs.rel||'').toLowerCase()==='stylesheet').length,images:imgs.length,lazyImages:imgs.filter(x=>(x.attrs.loading||'').toLowerCase()==='lazy').length,imagesMissingAlt:imgs.filter(x=>!('alt'in x.attrs)).length,imagesMissingDimensions:imgs.filter(x=>!x.attrs.width||!x.attrs.height).length,jsonLd:count(html,/<script\b[^>]*type\s*=\s*["']application\/ld\+json["'][^>]*>/gi),viewport:!!metas.find(x=>(x.attrs.name||'').toLowerCase()==='viewport'),hreflang:links.filter(x=>x.attrs.hreflang).length,hrefs,base};
}
function findings(model,response,responseMs,htmlBytes){
  const f=[]; const add=(category,severity,id,detail,recommendation)=>f.push({category,severity,id,detail,recommendation});
  if(responseMs>1000)add('performance',responseMs>2000?'error':'warning','slow-document-response',`${responseMs} ms initial response.`,'Inspect origin latency, caching and edge delivery.');
  if(htmlBytes>200000)add('performance','warning','large-html',`${(htmlBytes/1024).toFixed(1)} KiB HTML.`,'Reduce oversized inline payloads and duplicated markup.');
  if(model.scripts>20)add('performance','warning','many-scripts',`${model.scripts} external scripts.`,'Review third parties, bundling and hydration.');
  if(model.images&&model.lazyImages===model.images)add('performance','warning','all-images-lazy','Every image is lazy loaded.','Avoid lazy loading the above-the-fold LCP image.');
  if(model.imagesMissingDimensions)add('performance','warning','image-dimensions',`${model.imagesMissingDimensions} images lack width/height.`,'Reserve intrinsic aspect ratios to reduce CLS.');
  if(!model.viewport)add('performance','error','viewport','Viewport meta tag is missing.','Add a responsive viewport declaration.');
  if(!model.title)add('seo','error','title','Title is missing.','Add a unique descriptive title.');
  if(!model.description)add('seo','warning','description','Meta description is missing.','Add a useful page-specific description.');
  if(!model.canonical)add('seo','warning','canonical','Canonical URL is missing.','Add an intentional canonical URL.');
  if(!model.lang)add('seo','warning','lang','Document language is missing.','Declare html[lang].');
  if(!model.h1)add('seo','warning','h1','H1 is missing.','Add a clear primary heading.');
  if(model.robots&&/\bnoindex\b/i.test(model.robots))add('seo','warning','noindex',`robots=${model.robots}`,'Confirm noindex is intentional.');
  if(!model.jsonLd)add('seo','info','jsonld','No JSON-LD found.','Add accurate structured data where relevant.');
  if(model.imagesMissingAlt)add('accessibility','warning','image-alt',`${model.imagesMissingAlt} images lack alt attributes.`,'Provide alt text or explicit empty alt for decorative images.');
  const security=[['content-security-policy','CSP'],['strict-transport-security','HSTS'],['x-content-type-options','X-Content-Type-Options'],['referrer-policy','Referrer-Policy'],['permissions-policy','Permissions-Policy']];
  for(const [h,label] of security)if(!response.headers.has(h))add('security',h==='content-security-policy'?'warning':'info',`missing-${h}`,`${label} is missing.`,`Define and test an appropriate ${label} policy.`);
  return f;
}
async function audit(url){
  const x=await fetchText(url); const model=pageModel(x.text,x.url); const bytes=Buffer.byteLength(x.text); const fs=findings(model,x.response,x.responseMs,bytes);
  return {url:hostnameUrl(url),finalUrl:x.url.toString(),status:x.response.status,responseMs:x.responseMs,htmlBytes:bytes,document:model,headers:headersObj(x.response.headers),findings:fs,summary:{errors:fs.filter(v=>v.severity==='error').length,warnings:fs.filter(v=>v.severity==='warning').length,info:fs.filter(v=>v.severity==='info').length}};
}
async function jsonApi(url,{headers={}}={}){ const x=await safeFetch(url,{headers:{accept:'application/json',...headers}}); const body=await x.response.text(); let data; try{data=JSON.parse(body)}catch{throw new Error(`Expected JSON from ${url}; HTTP ${x.response.status}.`)} if(!x.response.ok)throw new Error(`HTTP ${x.response.status}: ${JSON.stringify(data).slice(0,500)}`); return data; }
function bearer(env){ const token=process.env[env]; if(!token)throw new Error(`${env} is not configured in the MCP runtime environment.`); return {authorization:`Bearer ${token}`}; }
async function cfZone(domain){ const data=await jsonApi(`https://api.cloudflare.com/client/v4/zones?name=${encodeURIComponent(domain)}`,{headers:bearer('CLOUDFLARE_API_TOKEN')}); if(!data.success)throw new Error('Cloudflare API request failed.'); if(!data.result?.length)throw new Error(`No Cloudflare zone found for ${domain}.`); return data.result[0]; }
function configuredBase(name){ const v=process.env[name]; if(!v)throw new Error(`${name} is not configured.`); const u=new URL(v); if(u.protocol!=='https:')throw new Error(`${name} must use HTTPS.`); return u.origin; }
function wpAuth(){ const u=process.env.WORDPRESS_USERNAME,p=process.env.WORDPRESS_APP_PASSWORD; return u&&p?{authorization:`Basic ${Buffer.from(`${u}:${p}`).toString('base64')}`}:{ }; }
function wcAuth(){ const k=process.env.WOOCOMMERCE_KEY,s=process.env.WOOCOMMERCE_SECRET; if(!k||!s)throw new Error('WOOCOMMERCE_KEY and WOOCOMMERCE_SECRET are not configured.'); return {authorization:`Basic ${Buffer.from(`${k}:${s}`).toString('base64')}`}; }
async function runDocker(args){ const {stdout}=await execFileAsync('docker',args,{timeout:10000,maxBuffer:2_000_000,env:{...process.env}}); return stdout; }
function normalizeOrigin(base,value){ try{return new URL(value,base)}catch{return null} }

const handlers={
  async site_audit({url}){ return audit(url); },
  async http_inspect({url}){ const x=await fetchText(url); return {finalUrl:x.url.toString(),status:x.response.status,responseMs:x.responseMs,htmlBytes:Buffer.byteLength(x.text),headers:headersObj(x.response.headers)}; },
  async performance_audit({url}){ const a=await audit(url); return {...a,findings:a.findings.filter(f=>f.category==='performance')}; },
  async performance_assets({url,limit=25}){ const x=await fetchText(url); const base=x.url; const refs=[]; for(const s of tags(x.text,'script'))if(s.attrs.src)refs.push(['script',s.attrs.src]); for(const l of tags(x.text,'link'))if((l.attrs.rel||'').includes('stylesheet')&&l.attrs.href)refs.push(['stylesheet',l.attrs.href]); for(const i of tags(x.text,'img'))if(i.attrs.src)refs.push(['image',i.attrs.src]); const unique=[]; const seen=new Set(); for(const [type,raw] of refs){const u=normalizeOrigin(base,raw);if(!u||u.origin!==base.origin||seen.has(u.href))continue;seen.add(u.href);unique.push({type,url:u.href});if(unique.length>=limit)break;} for(const r of unique){try{const y=await safeFetch(r.url,{method:'HEAD',timeoutMs:7000});r.status=y.response.status;r.contentType=y.response.headers.get('content-type');r.contentLength=Number(y.response.headers.get('content-length'))||null;r.cacheControl=y.response.headers.get('cache-control');r.responseMs=y.responseMs;}catch(e){r.error=e.message;}} return {page:base.toString(),resources:unique}; },
  async seo_audit({url}){ const a=await audit(url); return {...a,findings:a.findings.filter(f=>f.category==='seo')}; },
  async seo_schema({url}){ const x=await fetchText(url); const blocks=[...x.text.matchAll(/<script\b[^>]*type\s*=\s*["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi)].map(m=>m[1].trim()); const parsed=[]; for(const raw of blocks){try{const data=JSON.parse(raw);const nodes=Array.isArray(data)?data:(data['@graph']||[data]);parsed.push({valid:true,types:nodes.flatMap(n=>Array.isArray(n?.['@type'])?n['@type']:[n?.['@type']]).filter(Boolean)});}catch(e){parsed.push({valid:false,error:e.message});}} return {url:x.url.toString(),blocks:parsed,total:blocks.length,invalid:parsed.filter(x=>!x.valid).length}; },
  async seo_indexability({url}){ const a=await audit(url); const robots=await handlers.robots_inspect({url}).catch(e=>({error:e.message})); return {url:a.finalUrl,status:a.status,robotsMeta:a.document.robots,canonical:a.document.canonical,indexable:a.status>=200&&a.status<300&&!/\bnoindex\b/i.test(a.document.robots||''),robotsTxt:robots}; },
  async seo_links({url}){ const x=await fetchText(url); const base=x.url; const anchors=[...x.text.matchAll(/<a\b([^>]*)>([\s\S]*?)<\/a>/gi)].map(m=>{const a=attrs(`<a ${m[1]}>`);const u=a.href?normalizeOrigin(base,a.href):null;return {href:u?.href||a.href||null,text:m[2].replace(/<[^>]+>/g,' ').replace(/\s+/g,' ').trim().slice(0,160),internal:u?u.origin===base.origin:null,nofollow:(a.rel||'').split(/\s+/).includes('nofollow')};}).filter(x=>x.href); return {url:base.toString(),total:anchors.length,internal:anchors.filter(x=>x.internal).length,external:anchors.filter(x=>x.internal===false).length,emptyAnchor:anchors.filter(x=>!x.text).length,nofollow:anchors.filter(x=>x.nofollow).length,links:anchors.slice(0,200)}; },
  async seo_llm({url}){ const x=await fetchText(url); const origin=x.url.origin; const [llms,robots]=await Promise.all([fetchText(`${origin}/llms.txt`).catch(()=>null),fetchText(`${origin}/robots.txt`).catch(()=>null)]); const aiBots=['GPTBot','ChatGPT-User','OAI-SearchBot','ClaudeBot','Google-Extended','PerplexityBot']; const robotText=robots?.text||''; return {url:x.url.toString(),llmsTxt:{present:!!llms&&llms.response.ok,status:llms?.response.status||null,preview:llms?.response.ok?llms.text.slice(0,2000):null},aiCrawlerMentions:Object.fromEntries(aiBots.map(b=>[b,new RegExp(`User-agent:\\s*${b}`,'i').test(robotText)])),jsonLdBlocks:count(x.text,/<script\b[^>]*type\s*=\s*["']application\/ld\+json["']/gi),semantic:{lang:pageModel(x.text,x.url).lang,title:pageModel(x.text,x.url).title,description:pageModel(x.text,x.url).description}}; },
  async accessibility_audit({url}){ const x=await fetchText(url); const m=pageModel(x.text,x.url); const buttons=tags(x.text,'button'); const inputs=tags(x.text,'input'); const labels=tags(x.text,'label'); const landmarks={main:count(x.text,/<main\b/gi),nav:count(x.text,/<nav\b/gi),header:count(x.text,/<header\b/gi),footer:count(x.text,/<footer\b/gi)}; const issues=[]; if(!m.lang)issues.push({severity:'warning',id:'lang',detail:'Missing html[lang].'}); if(m.imagesMissingAlt)issues.push({severity:'warning',id:'img-alt',detail:`${m.imagesMissingAlt} images lack alt.`}); const unlabeledInputs=inputs.filter(i=>!i.attrs['aria-label']&&!i.attrs['aria-labelledby']&&!i.attrs.id).length; if(unlabeledInputs)issues.push({severity:'warning',id:'input-label',detail:`${unlabeledInputs} inputs have no obvious programmatic label hook.`}); return {url:x.url.toString(),headings:{h1:m.h1,h2:m.h2},images:{total:m.images,missingAlt:m.imagesMissingAlt},forms:{inputs:inputs.length,labels:labels.length,unlabeledInputs},buttons:buttons.length,landmarks,issues}; },
  async security_headers({url}){ const a=await audit(url); return {url:a.finalUrl,status:a.status,headers:a.headers,findings:a.findings.filter(f=>f.category==='security')}; },
  async security_cookies({url}){ const x=await safeFetch(url); const raw=x.response.headers.getSetCookie?.()||[]; return {url:x.url.toString(),cookies:raw.map(c=>({name:c.split('=',1)[0],secure:/;\s*secure\b/i.test(c),httpOnly:/;\s*httponly\b/i.test(c),sameSite:(c.match(/;\s*samesite=([^;]+)/i)||[])[1]||null,path:(c.match(/;\s*path=([^;]+)/i)||[])[1]||null})),count:raw.length}; },
  async stack_detect({url}){ const x=await fetchText(url); const h=headersObj(x.response.headers),html=x.text; const tech=[]; const add=(name,evidence)=>{if(!tech.some(t=>t.name===name))tech.push({name,evidence});}; if(/wordpress|wp-content|wp-includes/i.test(html))add('WordPress','HTML paths/signatures'); if(/woocommerce/i.test(html))add('WooCommerce','HTML signature'); if(/__NEXT_DATA__|\/_next\//i.test(html))add('Next.js','Next.js assets/data'); if(/astro-island|\/_astro\//i.test(html))add('Astro','Astro island/assets'); if(/svelte/i.test(html))add('Svelte','HTML/runtime signature'); if(/cdn-cgi|cf-ray/i.test(JSON.stringify(h)))add('Cloudflare','Cloudflare response headers'); if(/googletagmanager|gtag\(/i.test(html))add('Google Analytics / GTM','Analytics scripts'); if(h.server)add(h.server,`server: ${h.server}`); if(h['x-powered-by'])add(h['x-powered-by'],`x-powered-by: ${h['x-powered-by']}`); return {url:x.url.toString(),technologies:tech,headers:{server:h.server||null,poweredBy:h['x-powered-by']||null,cfRay:h['cf-ray']||null}}; },
  async robots_inspect({url}){ const origin=new URL(hostnameUrl(url)).origin; const x=await fetchText(`${origin}/robots.txt`); const lines=x.text.split(/\r?\n/).map(s=>s.trim()).filter(Boolean); return {url:x.url.toString(),status:x.response.status,sitemaps:lines.filter(l=>/^sitemap:/i.test(l)).map(l=>l.replace(/^sitemap:\s*/i,'')),userAgents:lines.filter(l=>/^user-agent:/i.test(l)).map(l=>l.replace(/^user-agent:\s*/i,'')),disallow:lines.filter(l=>/^disallow:/i.test(l)).map(l=>l.replace(/^disallow:\s*/i,'')),preview:x.text.slice(0,5000)}; },
  async sitemap_inspect({url,limit=100}){ const origin=new URL(hostnameUrl(url)).origin; const x=await fetchText(`${origin}/sitemap.xml`); const locs=[...x.text.matchAll(/<loc>\s*([^<]+)\s*<\/loc>/gi)].map(m=>m[1].trim()); return {url:x.url.toString(),status:x.response.status,type:/<sitemapindex\b/i.test(x.text)?'index':/<urlset\b/i.test(x.text)?'urlset':'unknown',total:locs.length,entries:locs.slice(0,limit)}; },
  async page_compare({before,after}){ const [a,b]=await Promise.all([audit(before),audit(after)]); const metric=(key)=>({before:a[key],after:b[key],delta:typeof a[key]==='number'&&typeof b[key]==='number'?b[key]-a[key]:null}); return {before:a.finalUrl,after:b.finalUrl,responseMs:metric('responseMs'),htmlBytes:metric('htmlBytes'),findingCount:{before:a.findings.length,after:b.findings.length,delta:b.findings.length-a.findings.length},document:{scripts:{before:a.document.scripts,after:b.document.scripts},images:{before:a.document.images,after:b.document.images},title:{before:a.document.title,after:b.document.title}}}; },
  async cloudflare_zone({domain}){ const z=await cfZone(domain); return {id:z.id,name:z.name,status:z.status,paused:z.paused,type:z.type,nameServers:z.name_servers,plan:z.plan?.name||null}; },
  async cloudflare_dns({domain}){ const z=await cfZone(domain); const data=await jsonApi(`https://api.cloudflare.com/client/v4/zones/${z.id}/dns_records?per_page=100`,{headers:bearer('CLOUDFLARE_API_TOKEN')}); return {zone:{id:z.id,name:z.name},records:data.result.map(r=>({id:r.id,type:r.type,name:r.name,content:r.content,proxied:r.proxied,ttl:r.ttl}))}; },
  async cloudflare_workers(){ const account=process.env.CLOUDFLARE_ACCOUNT_ID;if(!account)throw new Error('CLOUDFLARE_ACCOUNT_ID is not configured.'); const data=await jsonApi(`https://api.cloudflare.com/client/v4/accounts/${encodeURIComponent(account)}/workers/scripts`,{headers:bearer('CLOUDFLARE_API_TOKEN')}); return {accountId:account,scripts:(data.result||[]).map(x=>({id:x.id,createdOn:x.created_on,modifiedOn:x.modified_on,etag:x.etag}))}; },
  async github_repo({repo}){ const headers={accept:'application/vnd.github+json','x-github-api-version':'2022-11-28'};if(process.env.GITHUB_TOKEN)headers.authorization=`Bearer ${process.env.GITHUB_TOKEN}`;const d=await jsonApi(`https://api.github.com/repos/${repo}`,{headers});return {fullName:d.full_name,private:d.private,defaultBranch:d.default_branch,language:d.language,archived:d.archived,openIssues:d.open_issues_count,visibility:d.visibility,pushedAt:d.pushed_at,license:d.license?.spdx_id||null}; },
  async github_actions({repo,limit=10}){ const headers={accept:'application/vnd.github+json','x-github-api-version':'2022-11-28'};if(process.env.GITHUB_TOKEN)headers.authorization=`Bearer ${process.env.GITHUB_TOKEN}`;const d=await jsonApi(`https://api.github.com/repos/${repo}/actions/runs?per_page=${limit}`,{headers});return {repo,runs:(d.workflow_runs||[]).map(r=>({id:r.id,name:r.name,event:r.event,status:r.status,conclusion:r.conclusion,branch:r.head_branch,sha:r.head_sha,createdAt:r.created_at,updatedAt:r.updated_at,url:r.html_url}))}; },
  async wordpress_rest_index(){ const base=configuredBase('WORDPRESS_BASE_URL'); const d=await jsonApi(`${base}/wp-json/`,{headers:wpAuth()}); return {base,name:d.name,description:d.description,url:d.url,home:d.home,namespaces:d.namespaces,routes:Object.keys(d.routes||{}).slice(0,500)}; },
  async wordpress_plugins(){ const base=configuredBase('WORDPRESS_BASE_URL'); const d=await jsonApi(`${base}/wp-json/wp/v2/plugins?per_page=100`,{headers:wpAuth()}); return {base,plugins:d.map(p=>({plugin:p.plugin,status:p.status,name:p.name,version:p.version,author:p.author,networkOnly:p.network_only}))}; },
  async woocommerce_system_status(){ const base=configuredBase('WOOCOMMERCE_BASE_URL'); const d=await jsonApi(`${base}/wp-json/wc/v3/system_status`,{headers:wcAuth()}); return d; },
  async woocommerce_webhooks({limit=20}){ const base=configuredBase('WOOCOMMERCE_BASE_URL'); const d=await jsonApi(`${base}/wp-json/wc/v3/webhooks?per_page=${limit}`,{headers:wcAuth()}); return {base,webhooks:d.map(w=>({id:w.id,name:w.name,status:w.status,topic:w.topic,deliveryUrl:w.delivery_url,dateCreated:w.date_created,dateModified:w.date_modified}))}; },
  async docker_ps(){ const out=await runDocker(['ps','--format','{{json .}}']); return {containers:out.trim()?out.trim().split(/\r?\n/).map(l=>JSON.parse(l)):[]}; },
  async docker_inspect({container}){ return JSON.parse(await runDocker(['inspect',container])); },
  async docker_logs({container,lines=100}){ const {stdout,stderr}=await execFileAsync('docker',['logs','--tail',String(lines),container],{timeout:10000,maxBuffer:2_000_000}); return {container,lines,stdout,stderr}; }
};

async function dispatch(msg){
  if(msg.method==='server/discover') return {resultType:'complete',supportedVersions:['2026-07-28','2025-11-25','2025-06-18'],capabilities:{tools:{}},serverInfo:{name:'jedavid-web-tools',version:VERSION},instructions:'Read-only web engineering diagnostics. Start with site_audit; use narrower tools for root-cause analysis.'};
  if(msg.method==='initialize'){ const requested=msg.params?.protocolVersion; const supported=['2025-11-25','2025-06-18','2025-03-26','2024-11-05']; const protocolVersion=supported.includes(requested)?requested:'2025-11-25'; return {protocolVersion,capabilities:{tools:{listChanged:false}},serverInfo:{name:'jedavid-web-tools',version:VERSION},instructions:'Read-only web engineering diagnostics. Start with site_audit.'}; }
  if(msg.method==='ping') return {};
  if(msg.method==='tools/list') return {tools:TOOLS};
  if(msg.method==='tools/call'){ const name=msg.params?.name,args=msg.params?.arguments||{}; const fn=handlers[name]; if(!fn)throw Object.assign(new Error(`Unknown tool: ${name}`),{code:-32601}); return await fn(args); }
  if(msg.method?.startsWith('notifications/')) return null;
  throw Object.assign(new Error(`Method not found: ${msg.method}`),{code:-32601});
}

let buffer='';
process.stdin.setEncoding('utf8');
process.stdin.on('data',chunk=>{ buffer+=chunk; let idx; while((idx=buffer.indexOf('\n'))>=0){ const line=buffer.slice(0,idx).trim(); buffer=buffer.slice(idx+1); if(line) handleLine(line); }});
async function handleLine(line){ let msg; try{msg=JSON.parse(line)}catch{return;} if(!('id' in msg))return; try{const result=await dispatch(msg); if(result===null)return; const payload=msg.method==='tools/call'?textResult(result):result; process.stdout.write(JSON.stringify({jsonrpc:'2.0',id:msg.id,result:payload})+'\n');}catch(e){ if(msg.method==='tools/call'){process.stdout.write(JSON.stringify({jsonrpc:'2.0',id:msg.id,result:errResult(e)})+'\n');return;} process.stdout.write(JSON.stringify({jsonrpc:'2.0',id:msg.id,error:{code:e.code||-32603,message:e.message||String(e)}})+'\n'); }}
process.on('SIGTERM',()=>process.exit(0));
process.on('SIGINT',()=>process.exit(0));
