import type { NextConfig } from "next";

// When API_PROXY_TARGET is set the web proxies /api/* to the API service, so
// the browser only ever talks to the web origin and no CORS is involved. This
// is how the single-domain Render deployment avoids cross-origin entirely.
// A bare host (as Render's fromService supplies) is assumed to be https.
function resolveApiProxyTarget(): string | null {
  const raw = process.env.API_PROXY_TARGET?.trim().replace(/\/$/, "");
  if (!raw) return null;
  return /^https?:\/\//.test(raw) ? raw : `https://${raw}`;
}

const apiProxyTarget = resolveApiProxyTarget();

const nextConfig: NextConfig = {
  output: "standalone",
  reactStrictMode: true,
  poweredByHeader: false,
  async rewrites() {
    if (!apiProxyTarget) return [];
    return [{ source: "/api/:path*", destination: `${apiProxyTarget}/:path*` }];
  },
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "Content-Security-Policy", value: "frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action 'self'" },
          { key: "Referrer-Policy", value: "no-referrer" },
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "X-Frame-Options", value: "DENY" },
          { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=(), payment=(), usb=()" },
          { key: "Strict-Transport-Security", value: "max-age=31536000; includeSubDomains" },
        ],
      },
    ];
  },
};

export default nextConfig;
