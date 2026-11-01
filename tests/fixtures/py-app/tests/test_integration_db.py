import socket


def test_database_reachable():
    # needs a service named "db" listening on 5432; fails without it
    with socket.create_connection(("db", 5432), timeout=2):
        pass
