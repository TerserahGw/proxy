# Proxy Auto Checker

Upload semua isi ZIP ini ke root repository.

Fitur:
- Cek source proxy luar secara otomatis.
- Tambahkan proxy baru yang valid ke `verified-proxies.txt` dan `verified-proxies.json`.
- Cek ulang repo untuk menghapus proxy yang sudah tidak valid.
- Source milik repo kamu sendiri tidak dipakai sebagai input, hanya sebagai output.
- Versi ini memakai mode lebih cepat: kandidat proxy diacak dulu, timeout lebih rendah, concurrency lebih tinggi.

Workflow `.github/workflows/proxy-scan.yml` dan `.github/workflows/proxy-clean.yml` harus dibuat manual di GitHub.
