import { PasswordCard } from "@/components/settings/password-card";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { UserRound } from "lucide-react";

export const metadata = { title: "Akun — Owl" };

export default function AccountPage() {
  return (
    <div className="mx-auto max-w-6xl space-y-6 px-4 py-8">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Akun Saya</h1>
        <p className="text-sm text-muted-foreground">
          Pengaturan personal akun dashboard Owl — terpisah dari konfigurasi
          Cerberus engine.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <UserRound className="size-4" /> Profil
          </CardTitle>
          <CardDescription>
            Identitas login dashboard. Dikelola oleh user database Cerberus
            (fase E); manajemen user lainnya ada di halaman Users (khusus
            admin).
          </CardDescription>
        </CardHeader>
        <CardContent className="text-sm text-muted-foreground">
          Login dengan username dari halaman <code className="rounded bg-muted px-1">/login</code>;
          role &amp; status akun ditampilkan di Users.
        </CardContent>
      </Card>

      <PasswordCard />
    </div>
  );
}
