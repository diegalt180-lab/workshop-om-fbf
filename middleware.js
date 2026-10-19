// "Portero" del sitio: bloquea todo hasta que haya una sesión válida.
import { verifyToken, readCookie } from "./auth.js";

export default async function middleware(request) {
  const p = new URL(request.url).pathname;

  // Rutas siempre abiertas: la página de acceso, su API y los recursos internos de Vercel.
  if (
    p === "/acceso" ||
    p === "/acceso.html" ||
    p.startsWith("/api/acceso") ||
    p.startsWith("/_vercel")
  ) {
    return;
  }

  const tok = readCookie(request.headers.get("cookie") || "", "om_sess");
  if (tok && (await verifyToken(tok))) return; // sesión válida -> dejar pasar

  // Sin sesión -> a la página de acceso
  return Response.redirect(new URL("/acceso", request.url), 307);
}
