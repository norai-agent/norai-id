(function(){
  "use strict";
  // Values the build writes into the page (see the "credential-config" block in template.html)
  var CONFIG = JSON.parse(document.getElementById("credential-config").textContent);
  var EXPECTED_DOMAIN = CONFIG.domain;
  var PUBLISHED_FP = CONFIG.fingerprint;
  var checksEl = document.getElementById("checks");
  var rows = [
    ["doc","Credential norai.json fetched"],
    ["sig","Ed25519 signature on norai.json"],
    ["card","A2A Agent Card signed with the same key"],
    ["did","Same key in jwks.json and did.json"],
    ["valid","Valid and not revoked"],
    ["pgp","Operator’s signed declaration covers this site"],
    ["origin","Served from " + EXPECTED_DOMAIN],
    ["qr","QR fingerprint"]
  ];
  rows.forEach(function(r){
    var li=document.createElement("li"); li.id="c-"+r[0];
    li.innerHTML='<span class="what"></span><span class="pill">pending</span><span class="detail"></span>';
    li.querySelector(".what").textContent=r[1];
    checksEl.appendChild(li);
  });
  function set(id,state,detail){
    var li=document.getElementById("c-"+id); if(!li) return;
    var p=li.querySelector(".pill");
    p.className="pill "+(state==="ok"?"ok":state==="bad"?"bad":state==="warn"?"warn":"");
    p.textContent=({ok:"pass",bad:"fail",warn:"warning",skip:"n/a",run:"checking"})[state]||state;
    li.querySelector(".detail").textContent=detail||"";
  }
  function b64u(bytes){var s="";bytes=new Uint8Array(bytes);for(var i=0;i<bytes.length;i++)s+=String.fromCharCode(bytes[i]);return btoa(s).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");}
  function b64uDec(t){t=t.replace(/-/g,"+").replace(/_/g,"/");while(t.length%4)t+="=";var s=atob(t),o=new Uint8Array(s.length);for(var i=0;i<s.length;i++)o[i]=s.charCodeAt(i);return o;}
  function utf8(s){return new TextEncoder().encode(s);}
  function hex(buf){return Array.from(new Uint8Array(buf)).map(function(b){return b.toString(16).padStart(2,"0");}).join("");}
  function jcs(v){
    if(v===null||typeof v!=="object") return JSON.stringify(v);
    if(Array.isArray(v)) return "["+v.map(jcs).join(",")+"]";
    return "{"+Object.keys(v).sort().map(function(k){return JSON.stringify(k)+":"+jcs(v[k]);}).join(",")+"}";
  }
  async function thumb(x){
    var d=await crypto.subtle.digest("SHA-256",utf8('{"crv":"Ed25519","kty":"OKP","x":"'+x+'"}'));
    return b64u(d);
  }
  function humanFp(kid){var b=b64uDec(kid).slice(0,10),h="";for(var i=0;i<b.length;i++)h+=b[i].toString(16).padStart(2,"0");h=h.toUpperCase();return h.match(/.{1,4}/g).join(" ");}
  async function verifyDoc(doc,jwks){
    var body={};Object.keys(doc).forEach(function(k){if(k!=="signatures")body[k]=doc[k];});
    var payload=b64u(utf8(jcs(body)));
    var sig=(doc.signatures||[])[0]; if(!sig) return {ok:false,why:"no signature"};
    var hdr=JSON.parse(new TextDecoder().decode(b64uDec(sig.protected)));
    if(hdr.alg!=="EdDSA") return {ok:false,why:"algorithm "+hdr.alg+" not supported"};
    var jwk=(jwks.keys||[]).find(function(k){return k.kid===hdr.kid;});
    if(!jwk) return {ok:false,why:"kid not published in jwks.json"};
    if(await thumb(jwk.x)!==hdr.kid) return {ok:false,why:"kid is not the key thumbprint"};
    var key=await crypto.subtle.importKey("jwk",{kty:"OKP",crv:"Ed25519",x:jwk.x,ext:true},{name:"Ed25519"},false,["verify"]);
    var ok=await crypto.subtle.verify({name:"Ed25519"},key,b64uDec(sig.signature),utf8(sig.protected+"."+payload));
    return {ok:ok,kid:hdr.kid,why:ok?"kid "+hdr.kid:"signature does not match the content"};
  }
  async function getJSON(p){var r=await fetch(p,{cache:"no-store"});if(!r.ok)throw new Error(p+" → HTTP "+r.status);return r.json();}
  async function getText(p){var r=await fetch(p,{cache:"no-store"});if(!r.ok)throw new Error(p+" → HTTP "+r.status);return r.text();}
  function loadScript(src){return new Promise(function(res,rej){var s=document.createElement("script");s.src=src;s.onload=res;s.onerror=function(){rej(new Error("could not load "+src));};document.head.appendChild(s);});}

  async function run(){
    var fails=0,warns=0;
    rows.forEach(function(r){set(r[0],"run","");});
    var pill=document.getElementById("verdict-pill"),verdict=document.getElementById("verdict");
    pill.className="pill";pill.textContent="checking";verdict.textContent="Checking…";
    var doc,jwks,raw;
    try{ var rr=await fetch("norai.json",{cache:"no-store"}); if(!rr.ok) throw new Error("norai.json → HTTP "+rr.status); raw=new Uint8Array(await rr.arrayBuffer()); doc=JSON.parse(new TextDecoder().decode(raw)); jwks=await getJSON(".well-known/jwks.json"); set("doc","ok","serial "+doc.serial+", version "+doc.version); }
    catch(e){ set("doc","bad",e.message); fails++; }
    if(doc){
      try{ var r=await verifyDoc(doc,jwks); set("sig",r.ok?"ok":"bad",r.why); if(!r.ok)fails++; var mainKid=r.kid;
        try{ var card=await getJSON(".well-known/agent-card.json"); var rc=await verifyDoc(card,jwks);
          var same=rc.ok&&rc.kid===mainKid; set("card",same?"ok":"bad",same?"same identity key":rc.why); if(!same)fails++; }
        catch(e){ set("card","bad",e.message); fails++; }
        try{ var did=await getJSON(".well-known/did.json"); var vm=(did.verificationMethod||[]).find(function(m){return m.publicKeyJwk&&m.publicKeyJwk.kid===mainKid;});
          var eq=vm&&vm.publicKeyJwk.x===(jwks.keys.find(function(k){return k.kid===mainKid;})||{}).x;
          set("did",eq?"ok":"bad",eq?did.id:"did.json does not contain the identity key"); if(!eq)fails++; }
        catch(e){ set("did","bad",e.message); fails++; }
      }catch(e){
        var unsupported=/Ed25519|algorithm|Unrecognized|NotSupported/i.test(String(e&&(e.name+e.message)));
        set("sig",unsupported?"warn":"bad",unsupported?"This browser does not support Ed25519 in WebCrypto. Use src/agent_id/verify.py.":e.message);
        if(unsupported)warns++;else fails++;
        set("card","skip",""); set("did","skip","");
      }
      try{ var now=new Date(), exp=new Date(doc.validity.expires); var rev=await getJSON("revocations.json");
        var revoked=(rev.revoked||[]).some(function(x){return x.kid===(doc.keys&&doc.keys.identity.kid);});
        var okv=exp>now&&!revoked; set("valid",okv?"ok":"bad",revoked?"key revoked":(exp>now?"expires "+doc.validity.expires:"expired "+doc.validity.expires)); if(!okv)fails++; }
      catch(e){ set("valid","bad",e.message); fails++; }
      var stage="load";
      try{
        var asc=await getText("declaration.txt.asc");
        var pub=await getText("pgp/operator.asc");
        if(!window.openpgp) await loadScript("https://cdn.jsdelivr.net/npm/openpgp@5.11.2/dist/openpgp.min.js");
        stage="check";
        var key=await openpgp.readKey({armoredKey:pub}), res, text;
        if(asc.trim().indexOf("-----BEGIN PGP SIGNED MESSAGE-----")===0){
          var clear=await openpgp.readCleartextMessage({cleartextMessage:asc});
          res=await openpgp.verify({message:clear,verificationKeys:key}); text=clear.getText();
        } else {
          var bytes=new Uint8Array(await (await fetch("declaration.txt",{cache:"no-store"})).arrayBuffer());
          res=await openpgp.verify({message:await openpgp.createMessage({binary:bytes}),signature:await openpgp.readSignature({armoredSignature:asc}),verificationKeys:key,format:"binary"});
          text=new TextDecoder().decode(bytes);
        }
        await res.signatures[0].verified;
        var fpr=key.getFingerprint().toUpperCase();
        if(fpr!==String(doc.operator.pgp.fingerprint).toUpperCase()) throw new Error("signed by a key other than the operator’s");
        var annex={}, tail=text.split("──────────────").pop();
        tail.split(/\r?\n/).forEach(function(l){var m=l.match(/^([a-z0-9-]+): (.+)$/);if(m)annex[m[1]]=m[2].trim();});
        var man=new Uint8Array(await (await fetch("manifest.json",{cache:"no-store"})).arrayBuffer());
        var manifest=JSON.parse(new TextDecoder().decode(man));
        if(annex["site-manifest-sha256"]!==hex(await crypto.subtle.digest("SHA-256",man))) throw new Error("the declaration covers a different version of this site");
        if(manifest.files["norai.json"]!==hex(await crypto.subtle.digest("SHA-256",raw))) throw new Error("norai.json is not the file listed in manifest.json");
        if(annex["identity-key"]!==doc.keys.identity.kid) throw new Error("the declaration names a different agent key");
        set("pgp","ok","Declaration no. "+annex.declaration+" of "+annex.issued+", signed by "+key.getUserIDs()[0]);
      }catch(e){
        if(stage==="load"){ set("pgp","warn","Could not check in the browser ("+e.message+"). Use src/agent_id/verify.py"); warns++; }
        else { set("pgp","bad",e.message); fails++; }
      }
    } else { ["sig","card","did","valid","pgp"].forEach(function(id){set(id,"skip","");}); }
    var host=location.hostname;
    if(host===EXPECTED_DOMAIN){ set("origin","ok",host); }
    else { set("origin","warn","This copy is served from “"+(host||"a local file")+"”. Only the copy on "+EXPECTED_DOMAIN+" proves control of the domain."); warns++; }
    var q=new URLSearchParams(location.search).get("fp");
    if(q){ var exp2=PUBLISHED_FP.replace(/\s/g,""); var m=q.replace(/[^0-9a-f]/gi,"").toUpperCase()===exp2; set("qr",m?"ok":"bad",m?"The scanned QR matches the published key":"The QR does NOT match the published key"); if(!m)fails++; }
    else set("qr","skip","Open this page by scanning the credential QR to compare the fingerprint.");
    if(fails){pill.className="pill bad";pill.textContent="invalid";verdict.textContent=fails+" check(s) failed. Do not trust this credential.";}
    else if(warns){pill.className="pill warn";pill.textContent="valid with warnings";verdict.textContent="Signatures are correct. Review the warnings.";}
    else {pill.className="pill ok";pill.textContent="valid";verdict.textContent="All checks passed.";}
  }
  // Local / frontier bar: drawn from runtime.target_mix in norai.json, so it always matches the signed data.
  async function drawMix(){
    var bar=document.getElementById("mix"); if(!bar) return;
    try{
      var mix=(await getJSON("norai.json")).runtime.target_mix;
      var local=Math.max(0,Number(mix.local_percent)||0), frontier=Math.max(0,Number(mix.frontier_percent)||0);
      var total=local+frontier; if(!total) throw new Error("empty target_mix");
      var cols=[];
      [["mix-local",local,"LOCAL"],["mix-frontier",frontier,"FRONTIER"]].forEach(function(p){
        var el=document.getElementById(p[0]), share=p[1]/total;
        el.hidden=!p[1];
        el.textContent=share>=0.2?p[2]+" "+p[1]+"%":"";   // a label only where it fits
        if(p[1]) cols.push("minmax(0,"+p[1]+"fr)");
      });
      bar.style.gridTemplateColumns=cols.join(" ");
      bar.setAttribute("aria-label","Target split: "+local+"% local, "+frontier+"% frontier");
      document.getElementById("mix-local-text").textContent="Target: "+local+"% of requests on local models";
      document.getElementById("mix-frontier-text").textContent=frontier+"% on frontier models";
    }catch(e){
      bar.hidden=true;
      document.getElementById("mix-local-text").textContent="Could not read the target split from norai.json ("+e.message+").";
    }
  }
  drawMix();

  document.getElementById("run-verify").addEventListener("click",function(){
    document.getElementById("verify").scrollIntoView({behavior:matchMedia("(prefers-reduced-motion: reduce)").matches?"auto":"smooth"});
    run();
  });
  if(new URLSearchParams(location.search).get("fp")) run();

  document.querySelectorAll("[data-copy]").forEach(function(b){
    b.addEventListener("click",function(){
      var t=b.getAttribute("data-copy");
      var done=function(){b.textContent="copied";setTimeout(function(){b.textContent="copy";},1500);};
      if(navigator.clipboard){navigator.clipboard.writeText(t).then(done,function(){var s=window.getSelection(),r=document.createRange();r.selectNodeContents(b.previousElementSibling);s.removeAllRanges();s.addRange(r);});}
    });
  });
})();
