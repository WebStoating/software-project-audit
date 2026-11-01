import sqlite3


def find(db, name):
    return db.execute("SELECT * FROM t WHERE n = ?", (name,))
