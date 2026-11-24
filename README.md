# Digital Footprint Self-Audit

Tool CLI async untuk mengaudit seberapa terekspos akun **milik sendiri** di internet,
dengan fokus pada platform yang populer di Indonesia.

## Fitur
- **Cek username di 27 platform** (YouTube, X, Telegram, Pinterest, Linktree, Kompasiana,
  Vidio, KaryaKarsa, Tokopedia, Wattpad, SoundCloud, Roblox, Steam, Chess.com, GitHub, dll.)
- **Data-driven**: daftar situs ada di [`sites.json`](sites.json); menambah platform cukup edit config
- **Jujur soal keterbatasan**: platform yang memblokir pengecekan otomatis (Instagram, TikTok,
  Facebook, Threads, Shopee, Kaskus, Saweria, Trakteer, PyPI) diberi status `manual` beserta
  link untuk dicek sendiri, bukan ditebak
- **Password breach check**: HIBP Pwned Passwords dengan *k-anonymity*; password tidak pernah
  dikirim, hanya 5 karakter pertama hash SHA-1
- **Email breach check**: HIBP Breached Account API (opsional, butuh `HIBP_API_KEY`)
- Request konkuren (`asyncio` + `aiohttp`) dibatasi semaphore, retry dengan exponential
  backoff, menghormati `Retry-After`
- Skor eksposur + laporan per kategori di terminal, laporan lengkap dalam JSON

## Instalasi
```bash
pip install aiohttp pytest
```

## Pemakaian
```bash
python footprint_audit.py -u username_kamu
python footprint_audit.py -u username_kamu -p          # + cek password (input tersembunyi)
set HIBP_API_KEY=xxxx                                    # Windows, opsional
python footprint_audit.py -e kamu@email.com -o report.json
```

Contoh output (dipotong):
```
-- Sosial Media --
[!] YouTube                found      https://www.youtube.com/@octocat
[!] Telegram               found      https://t.me/octocat
[?] Instagram              manual     https://www.instagram.com/octocat/

Username kamu terlihat di 11 dari 18 platform yang bisa dicek otomatis.
9 platform [?] perlu dicek manual lewat link di atas.
```

## Menambah platform
Tambahkan entri di `sites.json`. `{u}` diganti username:

| `check.type`    | Dianggap ditemukan jika...                                   |
|-----------------|--------------------------------------------------------------|
| `status`        | HTTP 200 (400/404/410 = tidak ditemukan)                      |
| `present`       | teks `marker` ada di halaman                                  |
| `absent`        | teks `marker` (pesan "not found") tidak ada di halaman         |
| `redirect`      | URL akhir tidak mengandung `marker` (mis. redirect ke /404)    |
| `json_nonempty` | response JSON tidak kosong                                     |
| `manual`        | tidak dicek; hanya diberi link                                 |

Selalu validasi aturan baru dengan satu username yang pasti ada dan satu yang pasti tidak ada.

## Testing
```bash
pytest test_footprint_audit.py
```

## Keterbatasan
- `found` berarti username tersebut ada, **belum tentu** milik kamu.
- Situs bisa mengubah tampilan/proteksi kapan saja; aturan di `sites.json` perlu dirawat.
- Rate limit (HTTP 429) dilaporkan sebagai `error`, bukan ditebak.

## Etika & Intended Use
Tool ini dibuat untuk **audit diri sendiri**. Tool ini sengaja tidak mengumpulkan email,
nomor telepon, atau data pribadi orang lain. Patuhi Terms of Service setiap platform.
