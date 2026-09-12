# 🛡️ AegisQL
> **Zero-Trust Just-In-Time (JIT) Data Access Bastion & AST Guardrail Engine**

🌍 *[🇮🇩 Baca dokumentasi dalam Bahasa Indonesia](#-aegisql-bahasa-indonesia)*

[![Docker Compose](https://img.shields.io/badge/Orchestration-Docker_Compose-blue?logo=docker)](https://www.docker.com/)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI_0.110+-009688?logo=fastapi)](https://fastapi.tiangolo.com/)
[![Security-AST](https://img.shields.io/badge/Security-SQLGlot_AST_Parser-orange)](https://github.com/tobymao/sqlglot)
[![Compliance](https://img.shields.io/badge/Audit-Cryptographic_Hash_Chaining-emerald)](#)

AegisQL is a data access gateway built on **Zero Trust Network Access (ZTNA)** principles, eliminating the need for static database credentials. It provides ephemeral Just-In-Time (JIT) data interrogation sessions, Abstract Syntax Tree (AST) level SQL syntax inspection, automatic masking of Personally Identifiable Information (PII) & financial data, and a tamper-proof audit trail based on cryptographic hash chaining.

---

## 🏛️ System Architecture

```text
[ Client Browser ]
       │  (HTTPS / Port 3000)
       ▼
┌──────────────────────────────────────────────────────────┐
│ Ingress & Bastion Workspace (Nginx Reverse Proxy)        (Public Zone)
└──────────────────────────────┬───────────────────────────┘
                               │  (Internal Ingress Routing)
                               ▼
┌──────────────────────────────────────────────────────────┐
│ AegisQL Core Security Engine (FastAPI)                   │
│                                                          │
│  ├─► [JIT Session Sentinel]  : TTL Countdown & Token Mgr │
│  ├─► [AST SQL Guardrail]     : AST Syntax & Limit Inject │
│  ├─► [Dynamic PII Masker]    : NIK/NPWP/Acc Masking      │
│  └─► [Tamper-Proof Ledger]   : SHA-256 Hash Chaining     │
└──────────────────────────────┬───────────────────────────┘
                               │  (Isolated TCP / isolated_data_net)
                               ▼
┌──────────────────────────────────────────────────────────┐
│ Target RDBMS Engine (MySQL 8.0 - Isolated Network)        (Restricted Zone)
│ * Port 3306 is NEVER exposed to Host OS or Public        │
└──────────────────────────────────────────────────────────┘


✨ Key Features
Zero-Client Web Bastion: No need for third-party desktop clients (like DBeaver or DataGrip). All data interrogations occur in a controlled, browser-based workspace.
Abstract Syntax Tree (AST) Guardrail: Analyzes SQL grammar using sqlglot. Strictly blocks destructive queries (DDL/DML like DROP, DELETE, UPDATE), prevents SQL chaining, and deterministically injects LIMIT clauses.
Just-In-Time (JIT) Ephemeral Access: Interrogation sessions have a strict Time-To-Live (TTL). Once the timer expires, the session is instantly locked and revoked.
Dynamic Data Masking (PII & Financial Protection): Sensitive data columns (e.g., National ID, Tax ID, Bank Accounts) are automatically masked at the backend level before being serialized to the client.
Tamper-Proof Audit Logging: Every query transaction is recorded with a cryptographically linked signature (SHA-256 hash-chained), enabling mathematical verification of the audit trail's forensic integrity.
🚀 Quick Start (Local Deployment)
Prerequisites
Docker Desktop (with Docker Compose v2)
Git
Installation Steps



Bash
# 1. Clone the repository
git clone [https://github.com/wmdhani/aegisql.git](https://github.com/wmdhani/aegisql.git)
cd aegisql

# 2. Setup environment variables
cp .env.example .env

# 3. Spin up the container orchestration
docker compose up -d --build


Access the system interfaces:
Web Bastion Workspace: http://localhost:3000
Interactive OpenAPI Docs: http://localhost:8000/docs
🔒 Threat Modeling & Security Posture
Detailed risk mitigation analysis based on the STRIDE matrix can be reviewed in the THREAT_MODEL.md file.
🛡️ AegisQL (Bahasa Indonesia)
Zero-Trust Just-In-Time (JIT) Data Access Bastion & AST Guardrail Engine
🌍 🇬🇧 Read documentation in English
AegisQL adalah gateway akses data yang dibangun berdasarkan prinsip Zero Trust Network Access (ZTNA) untuk mengeliminasi kebutuhan kredensial database statis. Sistem ini menyediakan sesi interogasi data sementara (Just-In-Time), inspeksi sintaks SQL di level AST (Abstract Syntax Tree), penyamaran otomatis data sensitif (PII & Finansial), dan jejak audit anti-manipulasi berbasis cryptographic hash chaining.
🏛️ Arsitektur Sistem



Plaintext
[ Client Browser ]
       │  (HTTPS / Port 3000)
       ▼
┌──────────────────────────────────────────────────────────┐
│ Ingress & Bastion Workspace (Nginx Reverse Proxy)        (Zona Publik)
└──────────────────────────────┬───────────────────────────┘
                               │  (Internal Ingress Routing)
                               ▼
┌──────────────────────────────────────────────────────────┐
│ AegisQL Core Security Engine (FastAPI)                   │
│                                                          │
│  ├─► [JIT Session Sentinel]  : TTL Countdown & Token Mgr │
│  ├─► [AST SQL Guardrail]     : AST Syntax & Limit Inject │
│  ├─► [Dynamic PII Masker]    : Sensor NIK/NPWP/Rekening  │
│  └─► [Tamper-Proof Ledger]   : SHA-256 Hash Chaining     │
└──────────────────────────────┬───────────────────────────┘
                               │  (Isolated TCP / isolated_data_net)
                               ▼
┌──────────────────────────────────────────────────────────┐
│ Target RDBMS Engine (MySQL 8.0 - Isolated Network)        (Zona Terisolasi)
│ * Port 3306 tidak pernah di-expose ke Host atau Publik   │
└──────────────────────────────────────────────────────────┘


✨ Fitur Kunci
Zero-Client Web Bastion: Tidak memerlukan aplikasi desktop pihak ketiga (seperti DBeaver atau DataGrip). Seluruh interogasi data berlangsung di antarmuka browser yang terkontrol.
Abstract Syntax Tree (AST) Guardrail: Menganalisis gramatikal SQL menggunakan sqlglot. Secara ketat memblokir query destruktif (DDL/DML seperti DROP, DELETE, UPDATE), mencegah eksekusi SQL chaining, dan menginjeksi klausa LIMIT secara deterministik.
Just-In-Time (JIT) Ephemeral Access: Sesi interogasi memiliki batas waktu hidup (Time-To-Live). Ketika waktu habis, akses otomatis dikunci dan dicabut seketika.
Dynamic Data Masking (PII & Financial Protection): Data sensitif seperti NIK, NPWP, dan Nomor Rekening disamarkan secara otomatis di level backend sebelum data dirender ke antarmuka klien.
Tamper-Proof Audit Logging: Setiap transaksi query dicatat dengan tanda tangan kriptografis yang saling berantai (SHA-256 hash-chained), memungkinkan verifikasi integritas forensik jejak audit secara matematis.
🚀 Panduan Memulai (Deployment Lokal)
Prasyarat
Docker Desktop (dengan Docker Compose v2)
Git
Langkah Instalasi



Bash
# 1. Clone repositori
git clone [https://github.com/wmdhani/aegisql.git](https://github.com/wmdhani/aegisql.git)
cd aegisql

# 2. Siapkan file environment
cp .env.example .env

# 3. Jalankan orkestrasi container
docker compose up -d --build


Akses antarmuka sistem:
Web Bastion Workspace: http://localhost:3000
Dokumentasi OpenAPI Interaktif: http://localhost:8000/docs
🔒 Threat Modeling & Security Posture
Rincian analisis mitigasi risiko berbasis matriks STRIDE dapat ditinjau secara lengkap pada berkas THREAT_MODEL.md.
📄 Lisensi
Didistribusikan di bawah Lisensi MIT.
