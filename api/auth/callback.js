// Recibe el retorno de Google, valida el correo contra la lista y abre la sesión.
import { signToken, readCookie, isAllowedEmail } from "../../auth.js";

export const config = { runtime: "edge" };

function redirect(to) {
  const h = new Headers();
  h.set("location", to);
  return { h };
}

function emailFromIdToken(idToken) {
  try {
    const part = idToken.split(".")[1];
    const b64 = part.replace(/-/g, "+").replace(/_/g, "/");
    const pad = b64 + "===".slice((b64.length + 3) % 4);
    const json = decodeURIComponent(
      atob(pad)
        .split("")
        .map((c) => "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2))
        .join("")
    );
    const o = JSON.parse(json);
    if (o.email_verified === false) return null;
    return o.email || null;
  } catch (e) {
    return null;
  }
}

export default async function handler(request) {
  const url = new URL(request.url);
  const host = request.headers.get("x-forwarded-host") || url.host;
  const proto = request.headers.get("x-forwarded-proto") || "https";
  const base = `${proto}://${host}`;
  const redirectUri = `${base}/api/auth/callback`;

  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const savedState = readCookie(request.headers.get("cookie") || "", "oauth_state");

  const back = (e) => {
    const { h } = redirect(`${base}/acceso${e ? "?e=" + e : ""}`);
    h.append("set-cookie", `oauth_state=; Path=/; Max-Age=0`);
    return new Response(null, { status: 307, headers: h });
  };

  if (!code || !state || state !== savedState) return back(1);

  // Intercambiar el código por tokens
  const body = new URLSearchParams({
    code,
    client_id: process.env.GOOGLE_CLIENT_ID || "",
    client_secret: process.env.GOOGLE_CLIENT_SECRET || "",
    redirect_uri: redirectUri,
    grant_type: "authorization_code",
  });
  let tj = {};
  try {
    const tr = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body,
    });
    tj = await tr.json();
  } catch (e) {
    return back(1);
  }
  if (!tj.id_token) return back(1);

  const email = emailFromIdToken(tj.id_token);
  if (!email || !isAllowedEmail(email)) return back(2); // correo no autorizado

  const tok = await signToken(30);
  const h = new Headers();
  h.set("location", `${base}/`);
  h.append(
    "set-cookie",
    `om_sess=${tok}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${60 * 60 * 24 * 30}`
  );
  h.append("set-cookie", `oauth_state=; Path=/; Max-Age=0`);
  return new Response(null, { status: 307, headers: h });
}
