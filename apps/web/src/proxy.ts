import { type NextRequest, NextResponse } from "next/server";

// UX only: send visitors without a session cookie to the login page before rendering the
// console. Authorisation is enforced by the API on every request regardless of this check.
const SESSION_COOKIE = "aegis_session";

export function proxy(request: NextRequest) {
  if (!request.cookies.has(SESSION_COOKIE)) {
    const url = request.nextUrl.clone();
    url.pathname = "/login";
    url.search = `?next=${encodeURIComponent(request.nextUrl.pathname)}`;
    return NextResponse.redirect(url);
  }
  return NextResponse.next();
}

export const config = {
  matcher: [
    "/dashboard/:path*",
    "/endpoints/:path*",
    "/events/:path*",
    "/detections/:path*",
    "/alerts/:path*",
    "/incidents/:path*",
    "/network/:path*",
    "/intelligence/:path*",
    "/assistant/:path*",
    "/analytics/:path*",
    "/reports/:path*",
    "/settings/:path*",
  ],
};
