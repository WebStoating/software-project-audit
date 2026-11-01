import sqlite3


def connect(path=":memory:"):
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT)")
    return conn


def find_user_unsafe(conn, name):
    # planted: SQL injection via f-string
    return conn.execute(f"SELECT id, name FROM users WHERE name = '{name}'").fetchall()


def find_user(conn, name):
    return conn.execute("SELECT id, name FROM users WHERE name = ?", (name,)).fetchall()


def add_user(conn, name):
    conn.execute("INSERT INTO users (name) VALUES (?)", (name,))
    conn.commit()
