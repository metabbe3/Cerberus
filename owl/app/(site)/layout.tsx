import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Cerberus — Policy Engine untuk AI Agents",
  description:
    "Setiap tool call dievaluasi sebelum dieksekusi. Proteksi deterministik OPA untuk autonomous agents.",
};

export default function SiteLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="site-clay min-h-screen flex flex-col">
      {children}
    </div>
  );
}
