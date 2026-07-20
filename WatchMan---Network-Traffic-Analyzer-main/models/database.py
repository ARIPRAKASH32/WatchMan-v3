"""
models/database.py — SQLite asynchronous logging integration.
"""
import sqlite3
import threading
import time
import logging
from pathlib import Path

log = logging.getLogger("watchman.db")

DB_PATH = Path(__file__).parent.parent / "logs" / "watchman.db"

_db_lock = threading.Lock()
_packet_buffer = []
_alert_buffer = []


def init_db():
    DB_PATH.parent.mkdir(exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute('PRAGMA journal_mode=WAL;')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                time TEXT, src TEXT, dst TEXT, proto TEXT, 
                size INTEGER, sport TEXT, dport TEXT
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                time TEXT, type TEXT, severity TEXT, 
                confidence INTEGER, detail TEXT, mitigation TEXT,
                ml_prediction TEXT, anomaly_score REAL, risk_score INTEGER,
                risk_level TEXT, action_taken TEXT
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS email_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                time TEXT, recipient TEXT, subject TEXT, 
                status TEXT, error_message TEXT
            )
        ''')
        # Safely migrate existing databases if new columns are not present
        for col, col_type in [
            ("ml_prediction", "TEXT"), ("anomaly_score", "REAL"),
            ("risk_score", "INTEGER"), ("risk_level", "TEXT"), ("action_taken", "TEXT")
        ]:
            try:
                conn.execute(f"ALTER TABLE alerts ADD COLUMN {col} {col_type};")
            except Exception:
                pass


def insert_packet(pkt: dict):
    with _db_lock:
        _packet_buffer.append(pkt)


def insert_alert(alert: dict):
    with _db_lock:
        _alert_buffer.append(alert)


def insert_email_log(log_entry: dict):
    """Directly insert an email log entry into SQLite (thread-safe and self-healing)."""
    with _db_lock:
        try:
            with sqlite3.connect(DB_PATH, timeout=5) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS email_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        time TEXT, recipient TEXT, subject TEXT, 
                        status TEXT, error_message TEXT
                    )
                ''')
                cursor.execute(
                    'INSERT INTO email_logs (time, recipient, subject, status, error_message) VALUES (?, ?, ?, ?, ?)',
                    (
                        log_entry.get('time', time.strftime('%Y-%m-%d %H:%M:%S')),
                        log_entry.get('recipient', 'Unknown'),
                        log_entry.get('subject', 'No Subject'),
                        log_entry.get('status', 'FAILED'),
                        log_entry.get('error_message', '')
                    )
                )
                conn.commit()
        except Exception as e:
            log.warning("Failed to insert email log into SQLite: %s", e)


def get_email_logs(limit: int = 50) -> list[dict]:
    """Retrieve recent email log entries from SQLite (newest first, self-healing)."""
    with _db_lock:
        try:
            with sqlite3.connect(DB_PATH, timeout=5) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS email_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        time TEXT, recipient TEXT, subject TEXT, 
                        status TEXT, error_message TEXT
                    )
                ''')
                cursor.execute('SELECT time, recipient, subject, status, error_message FROM email_logs ORDER BY id DESC LIMIT ?', (limit,))
                rows = cursor.fetchall()
                return [dict(r) for r in rows]
        except Exception as e:
            log.warning("Failed to fetch email logs from SQLite: %s", e)
            return []


def _db_worker():
    while True:
        time.sleep(5)  # flush every 5 seconds
        with _db_lock:
            pkts = _packet_buffer[:]
            alts = _alert_buffer[:]
            _packet_buffer.clear()
            _alert_buffer.clear()
            
        if not pkts and not alts:
            continue
            
        try:
            with sqlite3.connect(DB_PATH, timeout=5) as conn:
                cursor = conn.cursor()
                if pkts:
                    cursor.executemany(
                        'INSERT INTO packets (time, src, dst, proto, size, sport, dport) VALUES (?, ?, ?, ?, ?, ?, ?)',
                        [(p['time'], p['src'], p['dst'], p['proto'], p['size'], str(p['sport']), str(p['dport'])) for p in pkts]
                    )
                if alts:
                    cursor.executemany(
                        '''INSERT INTO alerts (
                            time, type, severity, confidence, detail, mitigation,
                            ml_prediction, anomaly_score, risk_score, risk_level, action_taken
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                        [(
                            a['time'], a['type'], a['severity'], a.get('confidence', 80), a['detail'], a.get('mitigation', ''),
                            a.get('ml_prediction', 'Normal'), float(a.get('anomaly_score', 0.0)), int(a.get('risk_score', 0)),
                            a.get('risk_level', 'Low'), a.get('action_taken', 'None')
                        ) for a in alts]
                    )
                conn.commit()
        except Exception as e:
            log.warning("Database flush error: %s (events dropped to prevent memory backup)", e)


db_thread = threading.Thread(target=_db_worker, daemon=True, name="watchman-db-writer")

def start_db():
    """Initialize SQLite tables and start the async flush thread."""
    init_db()
    db_thread.start()
    log.info("SQLite persistence layer active.")
