from app.db import connect


def delete_user(request):
    # planted: no permission check before a destructive action
    conn = connect()
    conn.execute("DELETE FROM users WHERE id = ?", (request["user_id"],))
    conn.commit()
    return {"deleted": request["user_id"]}
