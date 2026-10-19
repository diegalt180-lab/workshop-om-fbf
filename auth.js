// Firma/verificación de la cookie de sesión (Edge-compatible, sin dependencias).
const enc = new TextEncoder();

function secret() {
  return process.env.SESSION_SECRET || "dev-insecure-secret-change-me";
}

function b64url(buf) {
  const bytes = new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function hmac(msg) {
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret()),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(msg));
  return b64url(sig);
}

// Token = "<expiraciónMs>.<hmac>"
export async function signToken(days = 30) {
  const exp = String(Date.now() + days * 24 * 60 * 60 * 1000);
  return exp + "." + (await hmac(exp));
}

export async function verifyToken(tok) {
  if (!tok || tok.indexOf(".") < 0) return false;
  const i = tok.lastIndexOf(".");
  const payload = tok.slice(0, i);
  const mac = tok.slice(i + 1);
  const exp = parseInt(payload, 10);
  if (!exp || Date.now() > exp) return false;
  const expect = await hmac(payload);
  return mac === expect;
}

export function readCookie(cookieStr, name) {
  const m = (cookieStr || "").match(new RegExp("(?:^|; )" + name + "=([^;]+)"));
  return m ? decodeURIComponent(m[1]) : null;
}
