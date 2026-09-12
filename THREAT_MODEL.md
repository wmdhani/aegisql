# AegisQL Threat Model & Security Posture

Dokumen ini menguraikan metodologi mitigasi risiko dan pemodelan ancaman (*threat modeling*) yang diterapkan pada arsitektur AegisQL menggunakan kerangka kerja STRIDE.

## 1. Trust Boundaries & Network Zoning

AegisQL membagi lingkungan eksekusi ke dalam tiga zona isolasi jaringan Docker:
- **Public/Ingress Zone (`internal_control_net`):** Menampung Nginx Web Bastion dan FastAPI Gateway.
- **Restricted Data Zone (`isolated_data_net`):** Menampung target MySQL RDBMS. Zona ini memiliki status `internal: true`, memutus koneksi langsung dari host OS maupun internet publik.
- **Client Workspace:** Sesi eksekusi hanya dapat berlangsung di memori browser yang terautentikasi melalui header sesi ephemeral `X-Session-ID`.

---

## 2. Analisis Ancaman (STRIDE Matrix)

| Kategori Ancaman | Skenario Vektor Serangan | Mitigasi AegisQL |
| :--- | :--- | :--- |
| **Spoofing** | Aktor jahat memalsukan token otorisasi atau session ID. | Sesi JIT divalidasi state-nya di server memory/keystore dengan UUIDv4 unik dan TTL ketat (maksimal 60 menit). |
| **Tampering** | Operator atau penyerang internal memanipulasi rekaman audit log untuk menghapus jejak ekstraksi data. | **Cryptographic Hash Chaining (SHA-256):** Tiap entri log mengikat hash dari entri sebelumnya. Verifier otomatis mendeteksi diskontinuitas rantai jika satu byte log dimanipulasi. |
| **Repudiation** | Pengguna menyangkal telah mengeksekusi query ekstraksi data sensitif. | Setiap payload SQL mentah, SQL tersanitasi, timestamp ISO-8601 UTC, dan identitas operator dicatat secara *append-only*. |
| **Information Disclosure** | Kueri mengekstraksi nomor identitas (NIK, NPWP, Rekening Bank) secara massal. | **Dynamic Heuristic Masking:** Kolom yang cocok dengan pola PII disensor otomatis di level backend sebelum serialisasi JSON ke client. |
| **Denial of Service** | Query analitik tanpa batas (`SELECT *`) memicu *Out of Memory* (OOM) pada database engine. | **AST Limit Injection:** Parsing syntax tree menyuntikkan klausa `LIMIT 100` secara otomatis dan menimpa limit manual yang melampaui batas wajar. |
| **Elevation of Privilege** | Eksploitasi multi-statement SQL injection (`SELECT 1; DROP TABLE ...;`). | Penolakan multi-statement di level AST parsing dan pemblokiran total seluruh token DDL/DML selain `SELECT`. |

---

## 3. Batasan Desain & Rekomendasi Lanjutan
- **Distributed Session Sync:** Pada deployment multi-node, in-memory `SessionStore` dapat digantikan dengan Redis Cluster terenkripsi.
- **Row-Level Security (RLS):** Integrasi masa depan dapat mencakup filtering berbasis atribut user (ABAC) untuk membatasi akses baris tabel spesifik.