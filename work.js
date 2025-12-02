<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ACME 证书申请器</title>
<script src="https://cdn.jsdelivr.net/npm/node-forge@1.3.1/dist/forge.min.js"></script>
<style>
:root {
  --primary: #2563eb; --primary-hover: #1d4ed8;
  --bg: #f8fafc; --card: #ffffff;
  --text: #334155; --text-light: #64748b;
  --border: #e2e8f0; --danger: #ef4444; --success: #10b981; --warning: #f59e0b;
  --radius: 12px; --shadow: 0 4px 6px -1px rgba(0,0,0,0.1), 0 2px 4px -1px rgba(0,0,0,0.06);
}
body { margin:0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: var(--bg); color: var(--text); padding: 40px 20px; line-height: 1.6; }
.container { max-width: 800px; margin: 0 auto; }
.header { text-align: center; margin-bottom: 40px; }
.header h1 { font-size: 28px; font-weight: 800; color: #0f172a; margin: 0 0 8px 0; }
.header p { color: var(--text-light); margin: 0; }
.card { background: var(--card); border-radius: var(--radius); box-shadow: var(--shadow); padding: 30px; margin-bottom: 24px; border: 1px solid var(--border); transition: opacity 0.3s ease; }
.card.hidden { display: none; }
.step-head { display: flex; align-items: center; margin-bottom: 20px; padding-bottom: 15px; border-bottom: 1px solid var(--border); }
.step-badge { background: var(--primary); color: #fff; width: 28px; height: 28px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: bold; font-size: 14px; margin-right: 12px; }
.step-title { font-size: 18px; font-weight: 600; color: #0f172a; }
.form-group { margin-bottom: 20px; }
.label { display: block; font-size: 14px; font-weight: 500; margin-bottom: 6px; color: var(--text); }
.sub-label { font-size: 12px; color: var(--text-light); margin-top: 4px; }
input[type=text], input[type=email], select, textarea { width: 100%; padding: 10px 12px; border: 1px solid var(--border); border-radius: 8px; font-size: 14px; outline: none; transition: border-color 0.2s; background: #fff; box-sizing: border-box; font-family: monospace; }
input:focus, select:focus, textarea:focus { border-color: var(--primary); box-shadow: 0 0 0 3px rgba(37,99,235,0.1); }
textarea { resize: vertical; }
.btn-row { display: flex; gap: 12px; flex-wrap: wrap; }
.btn { background: var(--primary); color: #fff; border: none; padding: 10px 20px; border-radius: 8px; font-size: 14px; font-weight: 500; cursor: pointer; transition: background 0.2s; display: inline-flex; align-items: center; justify-content: center; }
.btn:hover { background: var(--primary-hover); }
.btn:disabled { opacity: 0.6; cursor: not-allowed; }
.btn-ghost { background: transparent; color: var(--text); border: 1px solid var(--border); }
.btn-ghost:hover { background: #f1f5f9; }
.btn-full { width: 100%; }
.radio-group { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; }
.radio-card { cursor: pointer; position: relative; }
.radio-card input { position: absolute; opacity: 0; }
.radio-box { border: 1px solid var(--border); border-radius: 8px; padding: 12px; text-align: center; transition: all 0.2s; font-weight: 500; font-size: 14px; }
.radio-card input:checked + .radio-box { border-color: var(--primary); background: #eff6ff; color: var(--primary); box-shadow: 0 0 0 2px var(--primary) inset; }
.alert { padding: 12px 16px; border-radius: 8px; font-size: 13px; margin-top: 10px; line-height: 1.5; }
.alert-warning { background: #fffbeb; color: #92400e; border: 1px solid #fcd34d; }
.alert-code { background: rgba(255,255,255,0.6); padding: 2px 5px; border-radius: 4px; font-family: monospace; font-weight: bold; user-select: all; }
.alert-info { background: #eff6ff; color: #1e40af; border: 1px solid #dbeafe; }
.dns-row { background: #f8fafc; border: 1px solid var(--border); border-radius: 8px; padding: 15px; margin-top: 10px; }
.dns-val { display: flex; gap: 10px; margin-top: 8px; }
.dns-val div { flex: 1; }
#toast { position: fixed; bottom: 30px; right: 30px; background: #fff; padding: 12px 24px; border-radius: 8px; box-shadow: 0 10px 25px -5px rgba(0,0,0,0.1); transform: translateY(100px); opacity: 0; transition: all 0.3s cubic-bezier(0.18, 0.89, 0.32, 1.28); border-left: 4px solid var(--primary); z-index: 100; font-size: 14px; font-weight: 500; }
#toast.show { transform: translateY(0); opacity: 1; }
#toast.error { border-left-color: var(--danger); }
</style>
</head>
<body>

<div class="container">
  <div class="header">
    <h1>ACME 证书申请器</h1>
    <p>单文件 · 零依赖 · 全参数 · 永久免费</p>
  </div>

  <div class="card" id="step1">
    <div class="step-head"><span class="step-badge">1</span><span class="step-title">选择 CA 服务商</span></div>
    
    <div class="radio-group">
      <label class="radio-card"><input type="radio" name="ca" value="le" checked><div class="radio-box">Let's Encrypt</div></label>
      <label class="radio-card"><input type="radio" name="ca" value="zerossl"><div class="radio-box">ZeroSSL</div></label>
      <label class="radio-card"><input type="radio" name="ca" value="google"><div class="radio-box">Google</div></label>
      <label class="radio-card"><input type="radio" name="ca" value="custom"><div class="radio-box">自定义</div></label>
    </div>

    <div id="googleTip" class="alert alert-warning" style="display:none">
      <strong>⚠️ Google ACME 需反向代理</strong><br>
      因浏览器 CORS 限制，请先在本地终端运行：<br>
      <code class="alert-code">npx local-cors-proxy --proxyUrl https://dv.acme-v02.api.pki.goog --port 9000</code><br>
      然后在本页下方地址栏填入：<code class="alert-code">http://localhost:9000/directory</code>
    </div>

    <div class="form-group" style="margin-top:20px">
      <label class="label">Directory URL (API地址)</label>
      <input type="text" id="acmeUrl" readonly>
    </div>

    <button class="btn btn-full" id="btnConnect">连接服务 &rarr;</button>
  </div>

  <div class="card hidden" id="step2">
    <div class="step-head"><span class="step-badge">2</span><span class="step-title">配置证书参数</span></div>

    <div class="form-group">
      <label class="label">域名列表 <span style="color:var(--danger)">*</span></label>
      <input type="text" id="domains" placeholder="例如: example.com, *.example.com">
      <div class="sub-label"><label><input type="checkbox" id="saveDomains"> 记住我的域名</label></div>
    </div>

    <div class="form-group">
      <label class="label">联系邮箱 <span style="color:var(--danger)">*</span></label>
      <input type="email" id="email" placeholder="用于接收到期提醒">
      <div class="sub-label"><label><input type="checkbox" id="saveEmail"> 记住我的邮箱</label></div>
    </div>

    <div id="eabSection" style="display:none; background:#fff1f2; padding:15px; border-radius:8px; border:1px solid #ffe4e6; margin-bottom:20px;">
      <label class="label" style="color:#be123c">EAB 凭据 (Google/ZeroSSL 必填)</label>
      <div style="display:flex; gap:10px; margin-top:10px;">
        <input type="text" id="eabKid" placeholder="Key ID (KID)">
        <input type="text" id="eabKey" placeholder="HMAC Key">
      </div>
      <div class="sub-label">ZeroSSL 请在仪表盘获取；Google 请在 GCP 获取。</div>
    </div>

    <div class="form-group">
      <label class="label">密钥配置 (自动生成)</label>
      <div style="display:flex; gap:10px;">
        <select id="keyAlgo">
          <option value="rsa2048">RSA 2048 (通用)</option>
          <option value="rsa4096">RSA 4096 (高安)</option>
          <option value="p256">ECC P-256 (快速)</option>
        </select>
        <button class="btn btn-ghost" id="btnRegenKey">重置密钥</button>
      </div>
    </div>

    <div class="form-group">
      <label><input type="checkbox" id="agreeTerms" checked> 我已阅读并同意 <a id="linkTerms" href="#" target="_blank" style="color:var(--primary)">服务条款</a></label>
    </div>

    <button class="btn btn-full" id="btnRegister">注册账户并创建订单 &rarr;</button>
    <div id="msgRegister" style="text-align:center; font-size:13px; margin-top:10px; color:var(--text-light)"></div>
  </div>

  <div class="card hidden" id="step3">
    <div class="step-head"><span class="step-badge">3</span><span class="step-title">DNS 所有权验证</span></div>
    <div class="alert alert-info">
      请前往您的域名 DNS 管理后台，添加以下 <strong>TXT</strong> 记录。<br>
      添加完成后，建议等待 1-5 分钟再点击验证。
    </div>
    
    <div id="dnsBox"></div>

    <div class="btn-row" style="margin-top:25px;">
      <button class="btn" id="btnVerify" style="flex:2">立即验证并签发</button>
      <button class="btn btn-ghost" onclick="location.reload()" style="flex:1">取消</button>
    </div>
    <div id="msgVerify" style="text-align:center; margin-top:10px; font-size:13px;"></div>
  </div>

  <div class="card hidden" id="step4">
    <div class="step-head"><span class="step-badge" style="background:var(--success)">✓</span><span class="step-title">证书签发成功</span></div>
    
    <div class="form-group">
      <label class="label">证书文件 (fullchain.pem)</label>
      <textarea id="resCert" rows="6" readonly></textarea>
      <button class="btn btn-ghost btn-full" style="margin-top:5px" onclick="dl('fullchain.pem', $('#resCert').value)">下载证书</button>
    </div>

    <div class="form-group">
      <label class="label">私钥文件 (private.key)</label>
      <textarea id="resKey" rows="4" readonly></textarea>
      <button class="btn btn-ghost btn-full" style="margin-top:5px" onclick="dl('private.key', $('#resKey').value)">下载私钥</button>
    </div>

    <div class="alert alert-info">
      <strong>格式转换提示：</strong><br>
      IIS/Tomcat 需要 PFX 格式，请使用 OpenSSL 转换：<br>
      <code class="alert-code" style="font-size:12px">openssl pkcs12 -export -out cert.pfx -inkey private.key -in fullchain.pem</code>
    </div>
  </div>

</div>
<div id="toast"></div>

<script>
const $ = s => document.querySelector(s);
const $$ = s => document.querySelectorAll(s);
const toast = (msg, err=false) => {
    const t = $('#toast');
    t.textContent = msg;
    t.className = err ? 'error show' : 'show';
    setTimeout(()=>t.className='', 4000);
};
const dl = (name, txt) => {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([txt],{type:'text/plain'}));
    a.download = name; a.click();
}

const DIRS = {
    le: 'https://acme-v02.api.letsencrypt.org/directory',
    zerossl: 'https://acme.zerossl.com/v2/DV90/directory',
    google: 'http://localhost:9000/directory',
    custom: ''
};
const TERMS = {
    le: 'https://letsencrypt.org/documents/LE-SA-v1.6-August-18-2025.pdf',
    zerossl: 'https://secure.trust-provider.com/repository/docs/Legacy/20250618_CertificateSubscriberAgreement_v_2_8_click.pdf'
};

let state = {
    dirUrl: '', newAccountUrl: '', newOrderUrl: '', newNonceUrl: '',
    accountKey: null,
    certKey: null,
    domains: [],
    auths: [],
    orderUrl: ''
};

$$('input[name="ca"]').forEach(r => r.onchange = () => {
    const v = r.value;
    $('#acmeUrl').value = DIRS[v] || '';
    $('#acmeUrl').readOnly = (v !== 'custom');
    $('#googleTip').style.display = (v === 'google') ? 'block' : 'none';
    $('#eabSection').style.display = (v === 'zerossl' || v === 'google') ? 'block' : 'none';
    $('#linkTerms').href = TERMS[v] || '#';
});
$('#acmeUrl').value = DIRS['le'];
$('#linkTerms').href = TERMS['le'];

$('#btnConnect').onclick = async () => {
    const btn = $('#btnConnect');
    btn.disabled = true; btn.innerText = '连接中...';
    try {
        const url = $('#acmeUrl').value;
        if(!url) throw new Error("请输入目录地址");
        
        const res = await fetch(url);
        if(!res.ok) throw new Error("无法访问目录，请检查网络或 CORS");
        const dir = await res.json();
        
        state.newAccountUrl = dir.newAccount;
        state.newOrderUrl = dir.newOrder;
        state.newNonceUrl = dir.newNonce;
        state.dirUrl = url;
        
        $('#step1').classList.add('hidden');
        $('#step2').classList.remove('hidden');
        
        if(localStorage.domains) $('#domains').value = localStorage.domains;
        if(localStorage.email) $('#email').value = localStorage.email;
        
        regenKeys();
        
    } catch(e) {
        toast(e.message, true);
    } finally {
        btn.disabled = false; btn.innerText = '连接服务 →';
    }
};

const regenKeys = () => {
    state.accountKey = forge.pki.rsa.generateKeyPair(2048);
    const algo = $('#keyAlgo').value;
    const bits = algo.includes('4096') ? 4096 : 2048; 
    state.certKey = forge.pki.rsa.generateKeyPair(bits);
    toast('新密钥已在内存中生成');
};
$('#btnRegenKey').onclick = regenKeys;

$('#btnRegister').onclick = async () => {
    const btn = $('#btnRegister');
    const msg = $('#msgRegister');
    const email = $('#email').value;
    const domainStr = $('#domains').value;
    
    if(!email || !domainStr) return toast("请填写完整信息", true);
    if(!$('#agreeTerms').checked) return toast("请同意条款", true);
    
    if($('#saveDomains').checked) localStorage.domains = domainStr;
    if($('#saveEmail').checked) localStorage.email = email;

    state.domains = domainStr.split(/[,，\s]+/).filter(x=>x);
    
    btn.disabled = true; btn.innerText = '处理中...';
    msg.innerText = '正在注册 ACME 账户...';
    
    try {
        const payloadAcc = {
            contact: [`mailto:${email}`],
            termsOfServiceAgreed: true
        };
        
        const kid = $('#eabKid').value.trim();
        const hmacKey = $('#eabKey').value.trim();
        if(kid && hmacKey) {
            payloadAcc.externalAccountBinding = await signEab(kid, hmacKey, state.newAccountUrl, state.accountKey);
        }

        const resAcc = await acmePost(state.newAccountUrl, payloadAcc);
        if(resAcc.status !== 201 && resAcc.status !== 200) throw new Error("账户注册失败");
        
        msg.innerText = '账户就绪，正在创建订单...';
        
        const payloadOrder = {
            identifiers: state.domains.map(d => ({type:'dns', value:d}))
        };
        const resOrder = await acmePost(state.newOrderUrl, payloadOrder);
        const order = await resOrder.json();
        state.orderUrl = resOrder.headers.get('Location');
        
        msg.innerText = '订单创建成功，正在获取验证信息...';
        state.auths = [];
        $('#dnsBox').innerHTML = '';
        
        for(let authUrl of order.authorizations) {
            const resAuth = await acmePost(authUrl, "");
            const auth = await resAuth.json();
            const domain = auth.identifier.value;
            const chall = auth.challenges.find(c => c.type === 'dns-01');
            
            const thumbprint = getThumbprint(state.accountKey);
            const keyAuth = chall.token + '.' + thumbprint;
            const recordVal = forge.util.encode64(
                forge.md.sha256.create().update(keyAuth).digest().data
            ).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
            
            state.auths.push({ domain, url: chall.url, keyAuth });
            
            $('#dnsBox').innerHTML += `
            <div class="dns-row">
                <div style="font-weight:bold; color:var(--primary)">${domain}</div>
                <div class="dns-val">
                    <div>
                        <div class="sub-label">主机记录 (Host)</div>
                        <input type="text" readonly value="_acme-challenge" onclick="this.select()">
                    </div>
                    <div style="flex:2">
                        <div class="sub-label">记录值 (TXT Value)</div>
                        <input type="text" readonly value="${recordVal}" onclick="this.select()">
                    </div>
                </div>
            </div>`;
        }
        
        $('#step2').classList.add('hidden');
        $('#step3').classList.remove('hidden');
        
    } catch(e) {
        console.error(e);
        toast(e.message, true);
        msg.innerText = '错误: ' + e.message;
    } finally {
        btn.disabled = false; btn.innerText = '注册账户并创建订单 →';
    }
};

$('#btnVerify').onclick = async () => {
    const btn = $('#btnVerify');
    const msg = $('#msgVerify');
    btn.disabled = true; btn.innerText = '验证中...';
    msg.innerText = '正在通知 CA 验证 DNS...';
    
    try {
        for(let item of state.auths) {
            await acmePost(item.url, { keyAuthorization: item.keyAuth });
        }
        
        let order;
        for(let i=0; i<15; i++) {
            await new Promise(r => setTimeout(r, 2000));
            const res = await acmePost(state.orderUrl, "");
            order = await res.json();
            msg.innerText = `当前状态: ${order.status} (尝试 ${i+1}/15)...`;
            
            if(order.status === 'valid') break; 
            if(order.status === 'ready') {
                msg.innerText = '验证通过，正在生成 CSR 并提交...';
                const csrPem = generateCsr(state.domains, state.certKey);
                const csrDer = forge.pem.decode(csrPem)[0].body;
                const csrB64 = forge.util.encode64(csrDer).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
                
                await acmePost(order.finalize, { csr: csrB64 });
            }
            if(order.status === 'invalid') {
                throw new Error("验证失败！请检查 DNS 记录是否生效，或稍后再试。");
            }
        }
        
        if(order.status !== 'valid') throw new Error("超时或状态异常");
        
        msg.innerText = '下载证书内容...';
        const resCert = await acmePost(order.certificate, "");
        const fullchain = await resCert.text();
        
        $('#resCert').value = fullchain;
        $('#resKey').value = forge.pki.privateKeyToPem(state.certKey);
        
        $('#step3').classList.add('hidden');
        $('#step4').classList.remove('hidden');
        toast('恭喜！证书签发成功');
        
    } catch(e) {
        console.error(e);
        toast(e.message, true);
        msg.innerText = '失败: ' + e.message;
    } finally {
        btn.disabled = false; btn.innerText = '立即验证并签发';
    }
};

async function acmePost(url, payload) {
    const resHead = await fetch(state.newNonceUrl, {method:'HEAD'});
    const nonce = resHead.headers.get('Replay-Nonce');
    
    const pKey = state.accountKey;
    const header = {
        url: url,
        alg: 'RS256',
        nonce: nonce,
        jwk: {
            kty: 'RSA',
            n: forge.util.encode64(pKey.n.toByteArrayUnsigned()).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
            e: forge.util.encode64(pKey.e.toByteArrayUnsigned()).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
        }
    };
    
    const payloadB64 = (payload === "") ? "" : 
        forge.util.encode64(JSON.stringify(payload)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const headerB64 = forge.util.encode64(JSON.stringify(header)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    
    const md = forge.md.sha256.create();
    md.update(headerB64 + '.' + payloadB64);
    const signature = pKey.sign(md);
    const sigB64 = forge.util.encode64(signature).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    
    const body = JSON.stringify({
        protected: headerB64,
        payload: payloadB64,
        signature: sigB64
    });
    
    return fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/jose+json' },
        body: body
    });
}

async function signEab(kid, hmacKey, url, accountKey) {
    const macKeyBytes = forge.util.decode64(hmacKey.replace(/-/g, '+').replace(/_/g, '/'));
    
    const jwk = {
        kty: 'RSA',
        n: forge.util.encode64(accountKey.n.toByteArrayUnsigned()).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
        e: forge.util.encode64(accountKey.e.toByteArrayUnsigned()).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
    };
    const payloadStr = JSON.stringify(jwk);
    const payloadB64 = forge.util.encode64(payloadStr).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    
    const header = { alg: "HS256", kid: kid, url: url };
    const headerB64 = forge.util.encode64(JSON.stringify(header)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    
    const hmac = forge.hmac.create();
    hmac.start('sha256', macKeyBytes);
    hmac.update(headerB64 + "." + payloadB64);
    const sig = hmac.digest().data;
    const sigB64 = forge.util.encode64(sig).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    
    return {
        protected: headerB64,
        payload: payloadB64,
        signature: sigB64
    };
}

function getThumbprint(key) {
    const jwk = {
        e: forge.util.encode64(key.e.toByteArrayUnsigned()).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
        kty: 'RSA',
        n: forge.util.encode64(key.n.toByteArrayUnsigned()).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
    };
    const sortedStr = `{"e":"${jwk.e}","kty":"RSA","n":"${jwk.n}"}`;
    
    const md = forge.md.sha256.create();
    md.update(sortedStr);
    return forge.util.encode64(md.digest().data).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function generateCsr(domains, keyPair) {
    const csr = forge.pki.createCertificationRequest();
    csr.publicKey = keyPair.publicKey;
    csr.setSubject([{ name: 'commonName', value: domains[0] }]);
    const altNames = domains.map(d => ({ type: 2, value: d }));
    csr.setAttributes([{
        name: 'extensionRequest',
        extensions: [{
            name: 'subjectAltName',
            altNames: altNames
        }]
    }]);
    csr.sign(keyPair.privateKey, forge.md.sha256.create());
    return forge.pki.certificationRequestToPem(csr);
}
</script>
</body>
</html>
