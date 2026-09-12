CREATE DATABASE IF NOT EXISTS dummy_finance_db;
USE dummy_finance_db;

-- 1. Tabel Wajib Pajak / Entitas Usaha (Simulasi Data Identitas Sensitif)
CREATE TABLE IF NOT EXISTS corporate_taxpayers (
    taxpayer_id INT AUTO_INCREMENT PRIMARY KEY,
    npwp VARCHAR(25) NOT NULL,
    company_name VARCHAR(150) NOT NULL,
    pic_nik VARCHAR(20) NOT NULL,
    pic_phone VARCHAR(20) NOT NULL,
    pic_email VARCHAR(100) NOT NULL,
    sector VARCHAR(50) NOT NULL,
    registered_date DATE NOT NULL
);

-- 2. Tabel Rekening & Settlement Finansial
CREATE TABLE IF NOT EXISTS financial_accounts (
    account_id INT AUTO_INCREMENT PRIMARY KEY,
    taxpayer_id INT NOT NULL,
    bank_name VARCHAR(50) NOT NULL,
    bank_account_number VARCHAR(30) NOT NULL,
    balance DECIMAL(15, 2) NOT NULL,
    last_audit_status VARCHAR(30) DEFAULT 'VERIFIED',
    FOREIGN KEY (taxpayer_id) REFERENCES corporate_taxpayers(taxpayer_id)
);

-- 3. Tabel Log Transaksi Faktur / Arus Kas
CREATE TABLE IF NOT EXISTS audit_transactions (
    transaction_id INT AUTO_INCREMENT PRIMARY KEY,
    account_id INT NOT NULL,
    transaction_code VARCHAR(50) UNIQUE NOT NULL,
    amount DECIMAL(15, 2) NOT NULL,
    direction ENUM('INFLOW', 'OUTFLOW') NOT NULL,
    transaction_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    flagged_for_review BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (account_id) REFERENCES financial_accounts(account_id)
);

-- Seed Dummy Records
INSERT INTO corporate_taxpayers (npwp, company_name, pic_nik, pic_phone, pic_email, sector, registered_date) VALUES
('01.345.678.9-123.000', 'PT Selaras Nusantara Tech', '1271021203950001', '081265432109', 'finance@selaras.co.id', 'Technology', '2021-04-15'),
('02.987.654.3-456.000', 'CV Maju Makmur Sentosa', '1271032508880004', '081398765432', 'tax@majumakmur.com', 'Logistics', '2022-08-20'),
('03.456.789.0-789.000', 'PT Deli Samudera Mineral', '1271041112920002', '082154321098', 'admin@delimineral.co.id', 'Mining', '2023-01-10');

INSERT INTO financial_accounts (taxpayer_id, bank_name, bank_account_number, balance, last_audit_status) VALUES
(1, 'Bank Mandiri', '1090012345678', 845000000.00, 'VERIFIED'),
(2, 'BCA', '8220987654', 123500000.50, 'UNDER_REVIEW'),
(3, 'BRI', '012301009876501', 3450000000.00, 'VERIFIED');

INSERT INTO audit_transactions (account_id, transaction_code, amount, direction, transaction_timestamp, flagged_for_review) VALUES
(1, 'TRX-2026-09-001', 54000000.00, 'INFLOW', '2026-09-01 10:15:00', FALSE),
(1, 'TRX-2026-09-002', 12500000.00, 'OUTFLOW', '2026-09-02 14:30:00', FALSE),
(2, 'TRX-2026-09-003', 250000000.00, 'INFLOW', '2026-09-05 09:00:00', TRUE),
(3, 'TRX-2026-09-004', 1200000000.00, 'OUTFLOW', '2026-09-10 16:45:00', FALSE);