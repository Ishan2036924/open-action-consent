// Approver page. The person's key never leaves this browser; JCS and JWS here must match the SDKs byte for byte.
const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const enc = new TextEncoder();
const b64u = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
function canonical(v) {
  if (v === null) return "null";
  if (v === true) return "true";
  if (v === false) return "false";
  if (typeof v === "number") { if (!Number.isSafeInteger(v)) throw new Error("integers only"); return String(v === 0 ? 0 : v); }
  if (typeof v === "string") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(canonical).join(",") + "]";
  return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canonical(v[k])).join(",") + "}";
}
async function sha(text) { return new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(text))); }
async function digest(value) { return "sha-256:" + b64u(await sha(canonical(value))); }
function db() {
  return new Promise((ok, bad) => {
    const r = indexedDB.open("oac-approver", 1);
    r.onupgradeneeded = () => r.result.createObjectStore("keys");
    r.onsuccess = () => ok(r.result); r.onerror = () => bad(r.error);
  });
}
async function store(op, key, value) {
  const d = await db();
  return new Promise((ok, bad) => {
    const tx = d.transaction("keys", op === "get" ? "readonly" : "readwrite"), s = tx.objectStore("keys");
    const r = op === "get" ? s.get(key) : s.put(value, key);
    r.onsuccess = () => ok(r.result); r.onerror = () => bad(r.error);
  });
}
async function thumbprint(jwk) { return b64u(await sha(canonical({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y }))); }
async function signJws(payload, typ) {
  const k = await store("get", "device");
  if (!k) throw new Error("This browser is not enrolled yet. Open /enroll first.");
  const head = b64u(enc.encode(canonical({ alg: "ES256", kid: k.kid, typ })));
  const body = b64u(enc.encode(canonical(payload)));
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, k.pair.privateKey, enc.encode(head + "." + body)));
  let s = BigInt("0x" + [...sig.slice(32)].map((b) => b.toString(16).padStart(2, "0")).join(""));
  if (s > N / 2n) s = N - s; // low-S, as the SDKs require (spec 3.3)
  const sBytes = s.toString(16).padStart(64, "0").match(/../g).map((h) => parseInt(h, 16));
  return head + "." + body + "." + b64u(new Uint8Array([...sig.slice(0, 32), ...sBytes]));
}
const post = (path, body) => fetch(path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) }).then(async (r) => ({ ok: r.ok, body: await r.json() }));
const el = (id) => document.getElementById(id);
function say(text) { el("status").textContent = text; }

async function enroll() {
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
  const pub = await crypto.subtle.exportKey("jwk", pair.publicKey);
  const jwk = { kty: "EC", crv: "P-256", x: pub.x, y: pub.y };
  const r = await post("api/enroll", { code: el("code").value, jwk });
  if (!r.ok) return say(r.body.error || "Enrolment refused.");
  await store("put", "device", { pair, kid: await thumbprint(jwk) });
  say("This browser can now approve actions.");
}

function row(table, label, value) {
  const tr = table.insertRow(); tr.insertCell().textContent = label; tr.insertCell().textContent = typeof value === "string" ? value : JSON.stringify(value);
}

async function showPreview() {
  const id = new URLSearchParams(location.search).get("r");
  const r = await fetch("api/preview?r=" + encodeURIComponent(id || ""));
  if (!r.ok) return say("This request is unknown or has expired.");
  const { preview, issuer, person } = await r.json();
  el("summary").textContent = preview.summary;
  const t = el("fields");
  for (const [k, v] of Object.entries(preview.fields)) row(t, k, v);
  for (const [k, v] of Object.entries(preview.details || {})) row(t, k + " (detail)", v);
  row(t, "can be undone", preview.undo.kind === "none" ? "NO: this cannot be undone" : preview.undo.kind);
  if (preview.cancel_policy) row(t, "cancellation", preview.cancel_policy.text);
  row(t, "who asks", preview.executor);
  el("buttons").hidden = false;
  el("approve").onclick = async () => {
    const now = Math.floor(Date.now() / 1000);
    const jti = b64u(crypto.getRandomValues(new Uint8Array(18)));
    const consent = { oac: "0.1", type: "consent", iss: issuer, sub: person, aud: preview.executor, jti, iat: now, exp: now + 300,
      items: [{ preview: await digest(preview), action: preview.action }], signer: { kind: "device" } };
    try {
      const res = await post("api/consent", { token: await signJws(consent, "oac-consent+jws") });
      say(res.ok ? "Approved. You can close this page." : res.body.error || "Not accepted.");
    } catch (e) { say(String(e.message || e)); }
    el("buttons").hidden = true;
  };
  el("decline").onclick = async () => { await post("api/decline", { r: id }); say("Declined. Nothing will run."); el("buttons").hidden = true; };
}
