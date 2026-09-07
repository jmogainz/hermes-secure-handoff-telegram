const { chromium } = require('playwright');
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { webcrypto } = require('node:crypto');
(async () => {
 const root=path.resolve(__dirname,'../web');
 const server=http.createServer((req,res)=>{
  const files={'/':'index.html','/index.html':'index.html','/app.js':'app.js','/styles.css':'styles.css','/style.css':'style.css'};
  const file=files[new URL(req.url,'http://localhost').pathname];
  if(!file||!fs.existsSync(path.join(root,file))){res.writeHead(404);return res.end();}
  const mime=file.endsWith('.js')?'application/javascript':file.endsWith('.css')?'text/css':'text/html';
  const headers={'Content-Type':mime};
  for(const item of JSON.parse(fs.readFileSync(path.join(root,'vercel.json'),'utf8')).headers||[])for(const h of item.headers)headers[h.key]=h.value;
  res.writeHead(200,headers);res.end(fs.readFileSync(path.join(root,file)));
 });
 await new Promise(r=>server.listen(0,'127.0.0.1',r));
 let browser;
 try{
  browser=await chromium.launch({headless:true,channel:process.env.PLAYWRIGHT_CHANNEL||'chrome'});
  const pair=await webcrypto.subtle.generateKey({name:'RSA-OAEP',modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'},true,['encrypt','decrypt']);
  const pub=await webcrypto.subtle.exportKey('jwk',pair.publicKey);
  const request={v:1,id:'qa_actual_sdk_roundtrip',publicKey:pub,expiresAt:Date.now()+300000};
  const encoded=Buffer.from(JSON.stringify(request)).toString('base64url');
  const page=await browser.newPage({viewport:{width:375,height:812}});
  const errors=[];page.on('pageerror',e=>errors.push(e.name));
  await page.addInitScript(()=>{window.__sent=[];window.TelegramWebviewProxy={postEvent:(kind,data)=>{if(kind==='web_app_data_send')window.__sent.push(JSON.parse(data).data);}};});
  const base=process.env.QA_BASE_URL||`http://127.0.0.1:${server.address().port}/`;
  await page.goto(base+'#request='+encoded+'&tgWebAppVersion=9.6&tgWebAppPlatform=ios&tgWebAppThemeParams=%7B%7D',{waitUntil:'networkidle'});
  const button=page.locator('#send-button');
  const ready=await button.isVisible();
  console.log(JSON.stringify({officialSDK:await page.evaluate(()=>Boolean(window.Telegram?.WebApp)),title:await page.locator('#page-title').innerText(),ready,overflow:await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),pageErrors:errors}));
  if(!ready)throw Error('Real SDK + Telegram appended fragment did not reach ready');
  await button.click();await page.waitForFunction(()=>window.__sent.length===1);
  const envelope=JSON.parse(await page.evaluate(()=>window.__sent[0]));
  const plaintext=await webcrypto.subtle.decrypt({name:'RSA-OAEP'},pair.privateKey,Buffer.from(envelope.ciphertext,'base64url'));
  if(Buffer.from(plaintext).toString()!=='telegram-roundtrip-ok')throw Error('dummy marker mismatch');
  console.log('PASS official Telegram SDK, native-bridge stub, real WebCrypto roundtrip');
  fs.mkdirSync(path.resolve(__dirname,'../artifacts'),{recursive:true});
  await page.screenshot({path:path.resolve(__dirname,'../artifacts/mini-app-mobile.png')});
 }finally{if(browser)await browser.close();await new Promise(r=>server.close(r));}
})().catch(e=>{console.error(e.message);process.exitCode=1;});
