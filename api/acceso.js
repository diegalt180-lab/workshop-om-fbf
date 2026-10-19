// Valida el código contra la lista (variable de entorno ACCESS_CODES) y abre la sesión.
import { signToken } from "../auth.js";

export const config = { runtime: "edge" };

export default async function handler(request) {
  if (request.method !== "POST") {
    return new Response("Method Not Allowed", { status: 405 });
  }

  let body = {};
  try {
    body = await request.json();
  } catch (e) {}

  const code = ((body && body.code) || "").toString().trim();
  const codes = (process.env.ACCESS_CODES || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

  if (!code || codes.indexOf(code) < 0) {
    return new Response(JSON.stringify({ ok: false }), {
      status: 401,
      headers: { "content-type": "application/json" },
    });
  }

  const tok = await signToken(30);
  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: {
      "content-type": "application/json",
      "set-cookie": `om_sess=${tok}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${60 * 60 * 24 * 30}`,
    },
  });
}
