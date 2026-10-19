// "Portero": bloquea todo el sitio hasta que haya sesión válida.
import { verifyToken, readCookie } from "./auth.js";

export default async function middleware(request) {
  const p = new URL(request.url).pathname;

  // Siempre abiertas: página de acceso, el flujo de login y los recursos de Vercel.
  if (
    p === "/acceso" ||
    p === "/acceso.html" ||
    p.startsWith("/api/auth") ||
    p.startsWith("/_vercel")
  ) {
    return;
  }

  const tok = readCookie(request.headers.get("cookie") || "", "om_sess");
  if (tok && (await verifyToken(tok))) return;

  return Response.redirect(new URL("/acceso", request.url), 307);
}
