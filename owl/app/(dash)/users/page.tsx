"use client";

import { useEffect, useState } from "react";
import { toast } from "sonner";
import {
  AlertCircle,
  KeyRound,
  Loader2,
  Lock,
  Plus,
  Shield,
  UserCheck,
  UserX,
  Users,
} from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { PageHeader } from "@/components/page-header";
import { Timestamp } from "@/components/timestamp";

interface UserItem {
  id: number;
  username: string;
  role: "admin" | "viewer";
  disabled: boolean;
  created_at: string;
  last_login_at?: string;
}

export default function UsersPage() {
  const [users, setUsers] = useState<UserItem[]>([]);
  const [currentUser, setCurrentUser] = useState<UserItem | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Create User dialog state
  const [createOpen, setCreateOpen] = useState(false);
  const [newUsername, setNewUsername] = useState("");
  const [newRole, setNewRole] = useState<"admin" | "viewer">("viewer");
  const [newPassword, setNewPassword] = useState("");
  const [createSubmitting, setCreateSubmitting] = useState(false);

  // Reset Password dialog state
  const [resetTargetUser, setResetTargetUser] = useState<UserItem | null>(null);
  const [disableTargetUser, setDisableTargetUser] = useState<UserItem | null>(null);
  const [resetPassword, setResetPassword] = useState("");
  const [resetSubmitting, setResetSubmitting] = useState(false);

  const isViewer = currentUser?.role === "viewer";

  const fetchUsers = async () => {
    try {
      setLoading(true);
      setError(null);

      // Fetch me to check current role
      const meRes = await fetch("/api/auth/me").catch(() => null);
      if (meRes?.ok) {
        const meData = (await meRes.json()) as { user?: UserItem };
        if (meData.user) {
          setCurrentUser(meData.user);
        }
      }

      const res = await fetch("/api/admin/users");
      if (!res.ok) {
        const body = (await res.json().catch(() => null)) as { error?: string } | null;
        throw new Error(body?.error || `Gagal memuat pengguna (HTTP ${res.status})`);
      }
      const data = (await res.json()) as UserItem[];
      setUsers(data);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Terjadi kesalahan saat memuat data";
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchUsers();
  }, []);

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    if (newPassword.length < 12) {
      toast.error("Kata sandi minimal 12 karakter");
      return;
    }
    try {
      setCreateSubmitting(true);
      const res = await fetch("/api/admin/users", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: newUsername,
          role: newRole,
          password: newPassword,
        }),
      });
      const body = (await res.json().catch(() => null)) as { user?: UserItem; error?: string } | null;
      if (!res.ok) {
        throw new Error(body?.error || "Gagal membuat pengguna");
      }
      toast.success(`Pengguna ${newUsername} berhasil didaftarkan`);
      setCreateOpen(false);
      setNewUsername("");
      setNewPassword("");
      setNewRole("viewer");
      fetchUsers();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Gagal membuat pengguna";
      toast.error(msg);
    } finally {
      setCreateSubmitting(false);
    }
  };

  const handleToggleDisabled = async (user: UserItem) => {
    const targetState = !user.disabled;
    const actionLabel = targetState ? "menonaktifkan" : "mengaktifkan kembali";
    try {
      const res = await fetch(`/api/admin/users/${user.id}/disable`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ disabled: targetState }),
      });
      if (!res.ok) {
        const body = (await res.json().catch(() => null)) as { error?: string } | null;
        throw new Error(body?.error || `Gagal ${actionLabel} pengguna`);
      }
      toast.success(`Pengguna ${user.username} berhasil ${targetState ? "dinonaktifkan" : "diaktifkan"}`);
      fetchUsers();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : `Gagal ${actionLabel} pengguna`;
      toast.error(msg);
    }
  };

  const handleResetPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!resetTargetUser) return;
    if (resetPassword.length < 12) {
      toast.error("Kata sandi minimal 12 karakter");
      return;
    }
    try {
      setResetSubmitting(true);
      const res = await fetch(`/api/admin/users/${resetTargetUser.id}/reset-password`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: resetPassword }),
      });
      if (!res.ok) {
        const body = (await res.json().catch(() => null)) as { error?: string } | null;
        throw new Error(body?.error || "Gagal mereset kata sandi");
      }
      toast.success(`Kata sandi pengguna ${resetTargetUser.username} berhasil direset`);
      setResetTargetUser(null);
      setResetPassword("");
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Gagal mereset kata sandi";
      toast.error(msg);
    } finally {
      setResetSubmitting(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <PageHeader
          title="Pengelolaan Pengguna"
          description="Kelola akun pengguna, peran otorisasi gateway (admin atau viewer), dan status kredensial."
        />
        {!isViewer && (
          <Button onClick={() => setCreateOpen(true)} className="gap-1.5 self-start sm:self-auto">
            <Plus className="size-4" />
            Tambah Pengguna
          </Button>
        )}
      </div>

      {isViewer && (
        <Alert>
          <Shield className="size-4" />
          <AlertTitle>Peran Viewer (Hanya Baca)</AlertTitle>
          <AlertDescription>
            Akun Anda memiliki izin peran viewer. Seluruh mutasi konfigurasi pengguna dan gateway dikunci di tingkat engine.
          </AlertDescription>
        </Alert>
      )}

      {error ? (
        <Alert variant="destructive">
          <AlertCircle className="size-4" />
          <AlertTitle>Gagal memuat data pengguna</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      ) : null}

      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Users className="size-5 text-muted-foreground" />
            <CardTitle>Daftar Pengguna Gateway</CardTitle>
          </div>
          <CardDescription>
            Akun terdaftar yang memiliki akses login ke dashboard kontrol Cerberus.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="space-y-2">
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-10 w-full" />
            </div>
          ) : users.length === 0 ? (
            <div className="py-8 text-center text-sm text-muted-foreground">
              Belum ada pengguna terdaftar.
            </div>
          ) : (
            <div className="rounded-md border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-16">ID</TableHead>
                    <TableHead>Nama Pengguna</TableHead>
                    <TableHead>Peran</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Dibuat Pada</TableHead>
                    <TableHead>Login Terakhir</TableHead>
                    {!isViewer && <TableHead className="text-right">Tindakan</TableHead>}
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {users.map((u) => (
                    <TableRow key={u.id}>
                      <TableCell className="font-mono text-xs text-muted-foreground">
                        {u.id}
                      </TableCell>
                      <TableCell className="font-medium">{u.username}</TableCell>
                      <TableCell>
                        {u.role === "admin" ? (
                          <Badge variant="default" className="bg-primary/90">
                            Admin
                          </Badge>
                        ) : (
                          <Badge variant="secondary">Viewer</Badge>
                        )}
                      </TableCell>
                      <TableCell>
                        {u.disabled ? (
                          <Badge variant="destructive" className="gap-1">
                            <UserX className="size-3" />
                            Nonaktif
                          </Badge>
                        ) : (
                          <Badge
                            variant="outline"
                            className="gap-1 border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400"
                          >
                            <UserCheck className="size-3" />
                            Aktif
                          </Badge>
                        )}
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        <Timestamp time={u.created_at} />
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {u.last_login_at ? (
                          <Timestamp time={u.last_login_at} />
                        ) : (
                          <span className="italic">Belum pernah login</span>
                        )}
                      </TableCell>
                      {!isViewer && (
                        <TableCell className="text-right">
                          <div className="flex items-center justify-end gap-2">
                            <Button
                              variant="outline"
                              size="sm"
                              className="h-8 gap-1 text-xs"
                              onClick={() => {
                                setResetTargetUser(u);
                                setResetPassword("");
                              }}
                            >
                              <KeyRound className="size-3" />
                              Reset Sandi
                            </Button>
                            {u.id !== currentUser?.id && (
                              <Button
                                variant={u.disabled ? "outline" : "ghost"}
                                size="sm"
                                className={`h-8 gap-1 text-xs ${
                                  u.disabled ? "text-emerald-600" : "text-destructive"
                                }`}
                                onClick={() => setDisableTargetUser(u)}
                              >
                                {u.disabled ? (
                                  <>
                                    <UserCheck className="size-3" />
                                    Aktifkan
                                  </>
                                ) : (
                                  <>
                                    <UserX className="size-3" />
                                    Nonaktifkan
                                  </>
                                )}
                              </Button>
                            )}
                          </div>
                        </TableCell>
                      )}
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Dialog Tambah Pengguna */}
      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Tambah Pengguna Baru</DialogTitle>
            <DialogDescription>
              Buat kredensial akun baru untuk operator atau auditor dashboard Cerberus.
            </DialogDescription>
          </DialogHeader>
          <form onSubmit={handleCreateUser} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="create-username">Nama Pengguna (Username)</Label>
              <Input
                id="create-username"
                required
                placeholder="misal: bima.auditor"
                value={newUsername}
                onChange={(e) => setNewUsername(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="create-role">Peran Otorisasi</Label>
              <Select
                value={newRole}
                onValueChange={(val) => setNewRole(val as "admin" | "viewer")}
              >
                <SelectTrigger id="create-role">
                  <SelectValue placeholder="Pilih peran" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="viewer">Viewer (Hanya Baca)</SelectItem>
                  <SelectItem value="admin">Admin (Akses Penuh)</SelectItem>
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">
                Peran viewer tidak dapat mengubah aturan kebijakan, memutar kunci, atau menyimpan perubahan sistem.
              </p>
            </div>
            <div className="space-y-2">
              <Label htmlFor="create-password">Kata Sandi Awal</Label>
              <Input
                id="create-password"
                type="password"
                required
                minLength={12}
                placeholder="Minimal 12 karakter"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
              />
              <p className="text-xs text-muted-foreground">
                Standar keamanan gateway mewajibkan kata sandi minimal 12 karakter (Argon2id).
              </p>
            </div>
            <DialogFooter>
              <Button
                type="button"
                variant="outline"
                onClick={() => setCreateOpen(false)}
                disabled={createSubmitting}
              >
                Batal
              </Button>
              <Button
                type="submit"
                disabled={createSubmitting || !newUsername || newPassword.length < 12}
              >
                {createSubmitting ? <Loader2 className="size-4 animate-spin" /> : <Lock className="size-4" />}
                Daftarkan Pengguna
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* Dialog Reset Sandi */}
      <Dialog
        open={resetTargetUser !== null}
        onOpenChange={(open) => {
          if (!open) setResetTargetUser(null);
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Reset Kata Sandi</DialogTitle>
            <DialogDescription>
              Atur ulang kata sandi untuk akun <strong>{resetTargetUser?.username}</strong>. Seluruh sesi aktif pengguna ini akan dicabut secara otomatis.
            </DialogDescription>
          </DialogHeader>
          <form onSubmit={handleResetPassword} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="reset-password">Kata Sandi Baru</Label>
              <Input
                id="reset-password"
                type="password"
                required
                minLength={12}
                placeholder="Minimal 12 karakter baru"
                value={resetPassword}
                onChange={(e) => setResetPassword(e.target.value)}
              />
            </div>
            <DialogFooter>
              <Button
                type="button"
                variant="outline"
                onClick={() => setResetTargetUser(null)}
                disabled={resetSubmitting}
              >
                Batal
              </Button>
              <Button
                type="submit"
                disabled={resetSubmitting || resetPassword.length < 12}
              >
                {resetSubmitting ? <Loader2 className="size-4 animate-spin" /> : <KeyRound className="size-4" />}
                Simpan Kata Sandi Baru
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    
      {/* Konfirmasi Nonaktifkan user — aksi destruktif (cabut akses + sesi) */}
      <AlertDialog
        open={!!disableTargetUser && !disableTargetUser.disabled}
        onOpenChange={(o) => {
          if (!o) setDisableTargetUser(null);
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              Nonaktifkan {disableTargetUser?.username ?? ""}?
            </AlertDialogTitle>
            <AlertDialogDescription>
              Akses dan semua sesi aktif pengguna ini dicabut segera. Bisa
              diaktifkan kembali nanti dari tabel user.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Batal</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              onClick={() => {
                if (disableTargetUser) void handleToggleDisabled(disableTargetUser);
                setDisableTargetUser(null);
              }}
            >
              Ya, Nonaktifkan
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
</div>
  );
}
