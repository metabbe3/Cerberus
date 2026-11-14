import { Nav } from "@/components/nav";
import { GlobalSafetyBanner } from "@/components/global-safety-banner";

// Every signed-in page shares the nav; /login lives outside this group.
export default function DashLayout({ children }: { children: React.ReactNode }) {
  return (
    <>
      <Nav />
      <div className="lg:pl-60">
        <GlobalSafetyBanner />
        <main className="mx-auto max-w-6xl px-4 py-8">{children}</main>
      </div>
    </>
  );
}
