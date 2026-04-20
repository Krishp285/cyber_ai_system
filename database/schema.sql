-- ============================================================
-- AI Cyber Threat Intelligence & Attack Prediction System
-- Database Schema
-- ============================================================

CREATE DATABASE IF NOT EXISTS cyber_ai_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE cyber_ai_db;

-- ============================================================
-- USERS TABLE (JWT Auth)
-- ============================================================
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(80) NOT NULL UNIQUE,
    email VARCHAR(120) NOT NULL UNIQUE,
    password_hash VARCHAR(256) NOT NULL,
    role ENUM('admin', 'analyst', 'viewer') DEFAULT 'analyst',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL,
    INDEX idx_username (username),
    INDEX idx_email (email)
);

-- ============================================================
-- NETWORK LOGS TABLE
-- ============================================================
CREATE TABLE IF NOT EXISTS network_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    source_ip VARCHAR(45) NOT NULL,
    destination_ip VARCHAR(45),
    source_port INT,
    destination_port INT,
    protocol VARCHAR(20),
    duration FLOAT DEFAULT 0,
    bytes_sent INT DEFAULT 0,
    bytes_received INT DEFAULT 0,
    packets_sent INT DEFAULT 0,
    packets_received INT DEFAULT 0,
    flags VARCHAR(50),
    service VARCHAR(50),
    action ENUM('ALLOW', 'DENY', 'DROP') DEFAULT 'ALLOW',
    country VARCHAR(50) DEFAULT 'Unknown',
    city VARCHAR(100) DEFAULT 'Unknown',
    latitude FLOAT DEFAULT 0,
    longitude FLOAT DEFAULT 0,
    INDEX idx_source_ip (source_ip),
    INDEX idx_timestamp (timestamp),
    INDEX idx_protocol (protocol)
);

-- ============================================================
-- ATTACK PREDICTIONS TABLE
-- ============================================================
CREATE TABLE IF NOT EXISTS attack_predictions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    log_id INT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    source_ip VARCHAR(45) NOT NULL,
    attack_type VARCHAR(100) NOT NULL,
    confidence FLOAT NOT NULL,
    risk_score FLOAT NOT NULL,
    risk_level ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') NOT NULL,
    model_used VARCHAR(50) DEFAULT 'RandomForest',
    is_anomaly BOOLEAN DEFAULT FALSE,
    anomaly_score FLOAT DEFAULT 0,
    features_json TEXT,
    FOREIGN KEY (log_id) REFERENCES network_logs(id) ON DELETE SET NULL,
    INDEX idx_attack_type (attack_type),
    INDEX idx_risk_level (risk_level),
    INDEX idx_source_ip (source_ip)
);

-- ============================================================
-- ALERTS TABLE
-- ============================================================
CREATE TABLE IF NOT EXISTS alerts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    alert_type VARCHAR(100) NOT NULL,
    severity ENUM('INFO', 'WARNING', 'HIGH', 'CRITICAL') NOT NULL,
    source_ip VARCHAR(45),
    message TEXT NOT NULL,
    details JSON,
    is_resolved BOOLEAN DEFAULT FALSE,
    resolved_at TIMESTAMP NULL,
    resolved_by INT,
    prediction_id INT,
    FOREIGN KEY (resolved_by) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (prediction_id) REFERENCES attack_predictions(id) ON DELETE SET NULL,
    INDEX idx_severity (severity),
    INDEX idx_timestamp (timestamp),
    INDEX idx_is_resolved (is_resolved)
);

-- ============================================================
-- BLOCKED IPS TABLE (Simulated Firewall)
-- ============================================================
CREATE TABLE IF NOT EXISTS blocked_ips (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL UNIQUE,
    reason VARCHAR(255) NOT NULL,
    blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    blocked_by INT,
    unblocked_at TIMESTAMP NULL,
    is_active BOOLEAN DEFAULT TRUE,
    attack_count INT DEFAULT 1,
    FOREIGN KEY (blocked_by) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_ip (ip_address),
    INDEX idx_is_active (is_active)
);

-- ============================================================
-- LOGIN ATTEMPTS TABLE (Brute Force Detection)
-- ============================================================
CREATE TABLE IF NOT EXISTS login_attempts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(80),
    ip_address VARCHAR(45) NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    success BOOLEAN DEFAULT FALSE,
    user_agent VARCHAR(512),
    INDEX idx_ip_timestamp (ip_address, timestamp),
    INDEX idx_username (username)
);

-- ============================================================
-- THREAT PREDICTIONS TABLE (Time-based)
-- ============================================================
CREATE TABLE IF NOT EXISTS threat_forecasts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    forecast_date DATE NOT NULL,
    predicted_attack_type VARCHAR(100),
    predicted_count INT,
    confidence_level FLOAT,
    generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    actual_count INT DEFAULT 0,
    INDEX idx_forecast_date (forecast_date)
);

-- ============================================================
-- SEED DATA: Default Admin User
-- password: Admin@123 (bcrypt hash)
-- ============================================================
INSERT IGNORE INTO users (username, email, password_hash, role) VALUES
('admin', 'admin@cyberai.local', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4oEqsOSXWa', 'admin'),
('analyst1', 'analyst@cyberai.local', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4oEqsOSXWa', 'analyst');

-- ============================================================
-- SEED: Some Blocked IPs for Demo
-- ============================================================
INSERT IGNORE INTO blocked_ips (ip_address, reason, attack_count) VALUES
('192.168.1.100', 'Repeated brute force attempts', 47),
('10.0.0.55', 'Port scan detected', 12),
('172.16.0.200', 'DoS attack pattern', 89);
