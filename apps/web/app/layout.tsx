import type { Metadata } from "next";
import type { ReactNode } from "react";
import { AuthProvider } from "../components/auth-provider";
import { webRuntimeConfig } from "../lib/runtime-config";
import "./globals.css";

export const metadata: Metadata = {
  title: "ZeroTOP | Zero-day Training Orchestration Platform",
  description: "최신 위협을 강의, 격리 환경과 동적 평가로 전환하는 AI 기반 실전형 사이버보안 훈련 플랫폼",
  icons: { icon: "/zerotop-logo.png" },
};

// Public endpoints are supplied by the deployment environment, so the root
// shell must be rendered by the running server rather than frozen at image build.
export const dynamic = "force-dynamic";

export default function RootLayout({ children }: Readonly<{ children: ReactNode }>) {
  const runtimeConfig = webRuntimeConfig();
  return (
    <html lang="ko">
      <body><AuthProvider runtimeConfig={runtimeConfig}>{children}</AuthProvider></body>
    </html>
  );
}
