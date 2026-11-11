import { Nav } from "@/components/nav";

// Every signed-in page shares the nav; /login lives outside this group.
export default function DashLayout({ children }: { children: React.ReactNode }) {
  return (
    <>
      <Nav />
      <main className="mx-auto max-w-6xl px-4 py-8">{children}</main>
    </>
  );
}
