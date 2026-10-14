import createNextIntlPlugin from "next-intl/plugin";

import { fileURLToPath } from "node:url";

// Static export: `NEXT_EXPORT=1 next build` produces a pure static directory at web/out,
// which can be dropped straight into an nginx web root. Development (next dev) does not set
// this variable, keeping the /api reverse proxy and hot reload.
const isExport = process.env.NEXT_EXPORT === "1";
// Vercel demo: the whole site runs on mock data, no backend, no /api reverse proxy needed.
const isMock = process.env.NEXT_PUBLIC_MOCK === "1";

/** @type {import('next').NextConfig} */
const nextConfig = {
  // Avoid a parent directory's lockfile affecting root inference and asset-path generation.
  turbopack: { root: fileURLToPath(new URL(".", import.meta.url)) },
  reactCompiler: true,
  // Allow dev resources (HMR) to be accessed from LAN IPs; add/remove as needed.
  // In dev, open /_next/* and HMR to any IPv4 origin (unaffected by changing LAN IPs).
  // Note: Next forbids a bare "*" for security, so use segmented wildcards; "*.*.*.*" matches any IPv4.
  allowedDevOrigins: ["*.*.*.*"],
  compiler: {
    removeConsole: process.env.NODE_ENV === "production",
  },
  ...(isExport
    ? {
        // Pure static export: no Node runtime; images unoptimized; each route produces <route>/index.html.
        output: "export",
        images: { unoptimized: true },
        trailingSlash: true,
      }
    : isMock
      ? {
          // Vercel mock demo: no backend, no /api reverse proxy needed.
          images: { unoptimized: true },
        }
      : {
          // Development: reverse-proxy /api/* to the Go backend (default :8787, overridable via AUTOPENTEST_API).
          async rewrites() {
            const backend = process.env.AUTOPENTEST_API ?? "http://localhost:8787";
            return [{ source: "/api/:path*", destination: `${backend}/api/:path*` }];
          },
        }),
};

// next-intl 플러그인. 요청 설정은 src/i18n/request.ts 에 둔다. i18n 경로 라우팅을
// 쓰지 않으므로 미들웨어는 추가하지 않는다(정적 내보내기 output: "export" 와 호환).
const withNextIntl = createNextIntlPlugin("./src/i18n/request.ts");

export default withNextIntl(nextConfig);
