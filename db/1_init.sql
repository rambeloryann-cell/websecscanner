CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scans (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    url TEXT NOT NULL,
    mode VARCHAR(10) NOT NULL,
    score INT,
    status VARCHAR(20) DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS scan_results (
    id INT AUTO_INCREMENT PRIMARY KEY,
    scan_id INT NOT NULL,
    category VARCHAR(50),
    check_name VARCHAR(100),
    check_mode VARCHAR(10),
    status VARCHAR(20),
    severity VARCHAR(20),
    description TEXT,
    recommendation TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS failed_logins (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45),
    attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
