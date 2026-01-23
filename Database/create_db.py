import sqlite3

conn = sqlite3.connect("scanner.db")
cursor = conn.cursor()

cursor.execute("PRAGMA foreign_keys = ON;")


cursor.execute("""
CREATE TABLE IF NOT EXISTS User (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL
);
""")


cursor.execute("""
CREATE TABLE IF NOT EXISTS Vulnerability (
    vuln_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    category TEXT,
    base_severity_rate REAL,
    description TEXT,
    remediation TEXT
);
""")


cursor.execute("""
CREATE TABLE IF NOT EXISTS Target (
    target_id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    method TEXT,
    body_params TEXT,
    query_params TEXT
);
""")


cursor.execute("""
CREATE TABLE IF NOT EXISTS Custom_Scan_Config (
    config_id INTEGER PRIMARY KEY AUTOINCREMENT
);
""")


cursor.execute("""
CREATE TABLE IF NOT EXISTS Scan (
    scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_type TEXT,
    status TEXT,
    initiated_at TEXT,
    completed_at TEXT,
    user_id INTEGER,
    target_id INTEGER,
    config_id INTEGER,
    FOREIGN KEY (user_id) REFERENCES User(user_id),
    FOREIGN KEY (target_id) REFERENCES Target(target_id),
    FOREIGN KEY (config_id) REFERENCES Custom_Scan_Config(config_id)
);
""")


cursor.execute("""
CREATE TABLE IF NOT EXISTS Scan_Result (
    result_id INTEGER PRIMARY KEY AUTOINCREMENT,
    vulnerable_path TEXT,
    payload_used TEXT,
    specific_severity_rate REAL,
    scan_id INTEGER,
    vuln_id INTEGER,
    FOREIGN KEY (scan_id) REFERENCES Scan(scan_id),
    FOREIGN KEY (vuln_id) REFERENCES Vulnerability(vuln_id)
);
""")


cursor.execute("""
CREATE TABLE IF NOT EXISTS Config_Vulnerabilities (
    config_id INTEGER,
    vuln_id INTEGER,
    PRIMARY KEY (config_id, vuln_id),
    FOREIGN KEY (config_id) REFERENCES Custom_Scan_Config(config_id),
    FOREIGN KEY (vuln_id) REFERENCES Vulnerability(vuln_id)
);
""")


conn.commit()
conn.close()

print("Database and tables created successfully.")
