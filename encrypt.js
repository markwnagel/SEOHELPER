// Encrypts a page with a password so it can sit on a public host.
// The output holds only ciphertext plus a small unlock form; the browser
// decrypts it with the Web Crypto API once the right password is entered.
//
// Usage: SITE_PASSWORD='...' node encrypt.js source.html output.html

const fs = require('fs');
const { webcrypto } = require('crypto');
const { subtle } = webcrypto;

const ITERATIONS = 600000;

async function main() {
  const [src, out] = process.argv.slice(2);
  const password = process.env.SITE_PASSWORD;
  if (!src || !out || !password) {
    console.error("Usage: SITE_PASSWORD='...' node encrypt.js source.html output.html");
    process.exit(1);
  }
  const plain = fs.readFileSync(src, 'utf8');
  const salt = webcrypto.getRandomValues(new Uint8Array(16));
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const base = await subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
  const key = await subtle.deriveKey({ name: 'PBKDF2', salt, iterations: ITERATIONS, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
  const cipher = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(plain)));
  const b64 = (u) => Buffer.from(u).toString('base64');
  const payload = JSON.stringify({ v: 1, iter: ITERATIONS, salt: b64(salt), iv: b64(iv), data: b64(cipher) });
  fs.writeFileSync(out, gate(payload));
  console.log(`Wrote ${out} (${fs.statSync(out).size} bytes)`);
}

function gate(payload) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>As Prompted</title>
<style>
  :root { --ink: #282624; --base: #ededed; --accent: #ff9c7d; --mauve: #5c4e4b; }
  * { box-sizing: border-box; }
  body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: var(--ink); color: var(--base); font-family: Georgia, "Times New Roman", serif; padding: 16px; }
  main { width: 100%; max-width: 420px; }
  .mark { font-family: "Helvetica Neue", Arial, sans-serif; font-size: clamp(2.6rem, 12vw, 4rem); letter-spacing: -.035em; line-height: 1; margin: 0 0 28px; }
  .mark span { display: inline-block; width: .07em; height: .72em; background: var(--accent); margin-left: .04em; vertical-align: -.04em; }
  label { display: block; font-size: .95rem; margin-bottom: 8px; }
  .row { display: flex; gap: 10px; }
  input { flex: 1; min-width: 0; padding: 14px 16px; font-size: 1rem; background: var(--ink); color: var(--base); border: 1px solid rgba(237,237,237,.35); }
  input:focus { outline: 2px solid var(--accent); outline-offset: 1px; }
  button { padding: 14px 20px; font-size: 1rem; background: var(--accent); color: var(--ink); border: 0; cursor: pointer; font-family: inherit; }
  button:hover { background: var(--base); }
  button:disabled { opacity: .6; cursor: wait; }
  :focus-visible { outline: 2px solid #6fb7ff; outline-offset: 3px; }
  #msg { min-height: 1.5em; margin-top: 12px; font-size: .9rem; color: var(--accent); }
  noscript p { color: var(--accent); }
</style>
</head>
<body>
<main>
  <h1 class="mark">as prompted<span aria-hidden="true"></span></h1>
  <form id="f" autocomplete="off">
    <label for="pw">Password</label>
    <div class="row">
      <input id="pw" type="password" autocomplete="current-password" required autofocus>
      <button id="go" type="submit">Enter &gt;</button>
    </div>
    <p id="msg" role="status" aria-live="polite"></p>
  </form>
  <noscript><p>This page needs JavaScript turned on.</p></noscript>
</main>
<script>
(function () {
  var P = ${payload};
  var KEY = 'as-prompted-pw';
  var form = document.getElementById('f'), input = document.getElementById('pw'), msg = document.getElementById('msg'), go = document.getElementById('go');
  function bytes(b64) { var s = atob(b64), u = new Uint8Array(s.length); for (var i = 0; i < s.length; i++) u[i] = s.charCodeAt(i); return u; }
  async function unlock(pw) {
    var base = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveKey']);
    var key = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt: bytes(P.salt), iterations: P.iter, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
    var plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytes(P.iv) }, key, bytes(P.data));
    return new TextDecoder().decode(plain);
  }
  function show(html, pw) {
    try { sessionStorage.setItem(KEY, pw); } catch (e) {}
    document.open(); document.write(html); document.close();
  }
  async function attempt(pw, silent) {
    go.disabled = true; if (!silent) msg.textContent = 'Checking…';
    try { show(await unlock(pw), pw); }
    catch (e) {
      try { sessionStorage.removeItem(KEY); } catch (e2) {}
      go.disabled = false;
      if (!silent) { msg.textContent = 'That password isn\\'t right. Try again.'; input.select(); }
    }
  }
  if (!window.crypto || !crypto.subtle) { msg.textContent = 'This browser can\\'t unlock the page. Try a recent Chrome, Safari, Firefox or Edge.'; go.disabled = true; return; }
  form.addEventListener('submit', function (e) { e.preventDefault(); attempt(input.value, false); });
  var saved = null; try { saved = sessionStorage.getItem(KEY); } catch (e) {}
  if (saved) attempt(saved, true);
})();
</script>
</body>
</html>
`;
}

main().catch((e) => { console.error(e); process.exit(1); });
