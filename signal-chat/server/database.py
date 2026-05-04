import sqlite3
import json
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "signal.db")


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_conn() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                net_id       TEXT PRIMARY KEY,
                password     TEXT NOT NULL,
                ik_pub       TEXT NOT NULL,
                spk_pub      TEXT NOT NULL,
                ik_sign_pub  TEXT,
                spk_sig      TEXT,
                fingerprint  TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS prekeys (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                net_id      TEXT NOT NULL,
                opk_pub     TEXT NOT NULL,
                used        INTEGER DEFAULT 0,
                FOREIGN KEY (net_id) REFERENCES users(net_id)
            );

            CREATE TABLE IF NOT EXISTS sessions (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                initiator_id    TEXT NOT NULL,
                responder_id    TEXT NOT NULL,
                ek_pub          TEXT NOT NULL,
                sender_ik_pub   TEXT NOT NULL,
                opk_pub_used    TEXT NOT NULL,
                ratchet_pub     TEXT NOT NULL,
                created_at      REAL DEFAULT (unixepoch('now'))
            );

            CREATE TABLE IF NOT EXISTS messages (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                sender      TEXT NOT NULL,
                recipient   TEXT NOT NULL,
                payload     TEXT NOT NULL,
                sent_at     REAL DEFAULT (unixepoch('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_messages_pair
                ON messages (sender, recipient, sent_at);
        """)
        # Migrate existing databases that pre-date SPK signing columns
        for col in ("ik_sign_pub", "spk_sig"):
            try:
                conn.execute(f"ALTER TABLE users ADD COLUMN {col} TEXT")
            except Exception:
                pass


def register_user(net_id: str, password: str, ik_pub: str, spk_pub: str, opk_pubs: list[str],
                  ik_sign_pub: str = None, spk_sig: str = None) -> bool:
    fingerprint = f"{ik_pub[:8].upper()}:{spk_pub[:8].upper()}"
    try:
        with get_conn() as conn:
            conn.execute(
                "INSERT INTO users (net_id, password, ik_pub, spk_pub, ik_sign_pub, spk_sig, fingerprint) VALUES (?,?,?,?,?,?,?)",
                (net_id, password, ik_pub, spk_pub, ik_sign_pub, spk_sig, fingerprint),
            )
            conn.executemany(
                "INSERT INTO prekeys (net_id, opk_pub) VALUES (?,?)",
                [(net_id, opk) for opk in opk_pubs],
            )
        return True
    except sqlite3.IntegrityError:
        return False


def get_user(net_id: str) -> sqlite3.Row | None:
    with get_conn() as conn:
        return conn.execute("SELECT * FROM users WHERE net_id=?", (net_id,)).fetchone()


def get_prekey_bundle(net_id: str) -> dict | None:
    with get_conn() as conn:
        user = conn.execute("SELECT * FROM users WHERE net_id=?", (net_id,)).fetchone()
        if not user:
            return None
        opk = conn.execute(
            "SELECT id, opk_pub FROM prekeys WHERE net_id=? AND used=0 LIMIT 1", (net_id,)
        ).fetchone()
        if opk:
            conn.execute("UPDATE prekeys SET used=1 WHERE id=?", (opk["id"],))
        return {
            "ik_pub":      user["ik_pub"],
            "spk_pub":     user["spk_pub"],
            "opk_pub":     opk["opk_pub"] if opk else None,
            "ik_sign_pub": user["ik_sign_pub"],
            "spk_sig":     user["spk_sig"],
            # "spk_sig":     "AAUHUSHUSH",
            "fingerprint": user["fingerprint"],
        }


def save_session(initiator_id, responder_id, ek_pub, sender_ik_pub, opk_pub_used, ratchet_pub):
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO sessions
               (initiator_id, responder_id, ek_pub, sender_ik_pub, opk_pub_used, ratchet_pub)
               VALUES (?,?,?,?,?,?)""",
            (initiator_id, responder_id, ek_pub, sender_ik_pub, opk_pub_used, ratchet_pub),
        )


def get_session(initiator_id, responder_id) -> sqlite3.Row | None:
    with get_conn() as conn:
        return conn.execute(
            """SELECT * FROM sessions WHERE initiator_id=? AND responder_id=?
               ORDER BY created_at DESC LIMIT 1""",
            (initiator_id, responder_id),
        ).fetchone()


def save_message(sender: str, recipient: str, payload: str):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO messages (sender, recipient, payload) VALUES (?,?,?)",
            (sender, recipient, payload),
        )


def get_history(user_a: str, user_b: str, limit: int = 200) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            """SELECT sender, recipient, payload, sent_at FROM messages
               WHERE (sender=? AND recipient=?) OR (sender=? AND recipient=?)
               ORDER BY sent_at ASC LIMIT ?""",
            (user_a, user_b, user_b, user_a, limit),
        ).fetchall()
        return [dict(r) for r in rows]


def list_users(exclude: str) -> list[str]:
    with get_conn() as conn:
        rows = conn.execute("SELECT net_id FROM users WHERE net_id != ?", (exclude,)).fetchall()
        return [r["net_id"] for r in rows]
