from app import db


def test_add_and_find_user():
    conn = db.connect()
    db.add_user(conn, "ada")
    assert db.find_user(conn, "ada")[0][1] == "ada"


def test_find_missing_user():
    assert db.find_user(db.connect(), "nobody") == []
