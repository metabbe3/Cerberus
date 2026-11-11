# Cerberus Design Philosophy

Dokumen ini = satu sumber kebenaran desain untuk SEMUA permukaan Cerberus (landing publik, docs, dashboard Owl, halaman baru). Dibaca manusia dan agent — saat membuat halaman baru, ikut dokumen ini, jangan karang gaya sendiri.

## Prinsip Umum
1. **Produk = internal company tools.** Tone profesional, tenang, tidak playful, tidak hype. Tidak ada angka marketing kosong (TPS, "10x faster") di permukaan publik — angka teknis hidup di docs/BENCH.md untuk evaluator teknis.
2. **Satu accent saja.** Landing: coral hangat `#FF7847` di atas cream `#F6F1E9`. Dashboard: primary existing shadcn. Accent dipakai untuk SATU aksi utama per layar, bukan dekorasi.
3. **Konsistensi > kreativitas per halaman.** Radius, shadow, spacing diambil dari token — jangan variasikan antar kartu.
4. **Aksesibilitas non-nego**: hormati `prefers-reduced-motion` (isi tetap utuh tanpa animasi), teks kecil tidak di atas accent (kontras rendah), focus state terlihat.

## Dua Mode Styling

### Mode A — Publik (landing `/`, `/docs-intro`): Claymorphism hangat
- Kenapa: permukaan wajah produk yang ramah namun dewasa; membedakan dari dashboard data-dense.
- Scope: SEMUA class clay di-scope `.site-clay` (wrapper layout `(site)`) — TIDAK BOLEH bocor ke dashboard.
- Token (globals.css `--clay-*`):
  - bg cream `#F6F1E9`, surface `#FFFFFF`, ink `#2D2A26`, muted `#665F55`
  - accent coral `#FF7847` (satu-satunya)
  - pastel pendukung hanya untuk chips/blob: mint `#BFE8D9`, lilac `#E3DBFF`, butter `#FFEFC2`, soft coral `#FFD9CC`
- Resep clay: radius kartu 28px konsisten; double shadow puffy (highlight terang atas-kiri + shadow gelap bawah-kanan, satu deklarasi box-shadow); pressed = inset flip + scale(0.98); blob drift halus (transform-only, 8–12s) atau ornamen geometris lembut — TIDAK animasi berlebihan.
- Tipografi: heading bold tracking-tight besar; body muted kontras cukup; mono untuk kode/keputusan.
- Struktur landing yang benar: capsule nav → hero (klaim jelas + demo decision card nyata: ALLOW/DENY terminal bubble) → cara kerja 3 langkah → fitur → SDK → CTA → footer rounded-top. TANPA stats band.

### Mode B — Dashboard Owl (`(dash)`): dark, dense, data-first
- Kenapa: operator butuh densitas informasi, bukan kehangatan. Tetap pakai komponen shadcn/radix existing.
- Aturan: tidak ada clay class di sini; tabel rapat, angka mono, status warna semantik (merah deny / hijau allow / amber warn); live-stream jelas statusnya (online/offline); aksi berbahaya selalu ada konfirmasi + warning merah saat mode fail-open.

## Do & Don't (anti AI-slop)
- DON'T: gradien ungu/biru generik, emoji berjejalan, kartu 3-kolom isi kosong, "Powered by AI", angka hype tanpa konteks, heading glow, border-radius aneh-aneh per kartu.
- DO: klaim spesifik + bukti (decision card nyata), hierarchy jelas (1 H1), whitespace lega, satu CTA utama, copy bahasa Indonesia formal ringkas.

## Motion
- Animasi hanya: blob drift lambat, hover lift 2px, pressed state, fade-in section (opsional).
- Semua wajib mati saat `prefers-reduced-motion: reduce`.
- Tidak ada parallax, tidak ada auto-carousel, tidak ada marquee.

## Checklist halaman baru
1. Halaman publik atau dashboard? (pilih Mode A/B)
2. Token dipakai dari globals — tidak hardcode hex baru?
3. Satu accent, satu CTA utama?
4. Reduced-motion dihormati?
5. Mobile: grid stack, nav pill scrollable?
6. Tidak ada angka marketing / hype?
7. (Untuk agent AGY: sebelum menulis page baru, baca dokumen ini dulu.)
