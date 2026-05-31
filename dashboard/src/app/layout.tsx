import type { Metadata } from "next";
import { Nav } from "@/components/Nav";
import { Providers } from "./providers";
import "./globals.css";

export const metadata: Metadata = {
  title: "SentinelLite — Autonomous SOC",
  description: "Mini autonomous SOC: triage, investigation, and response.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="min-h-screen antialiased">
        <Providers>
          <Nav />
          <main className="mx-auto max-w-[1400px] px-4 py-6">{children}</main>
        </Providers>
      </body>
    </html>
  );
}
