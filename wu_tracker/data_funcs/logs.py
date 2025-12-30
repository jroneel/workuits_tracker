from contextlib import closing
import streamlit as st
import sqlite3

from wu_tracker.data_funcs.get_connection import get_connection

def get_log(id)->sqlite3.Row:
    conn = get_connection()
    with closing(conn):
        rows = conn.execute(
            """
            SELECT tl.*, c.name AS client_name, tt.name AS task_type_name
            FROM task_logs tl
            JOIN clients c ON tl.client_id = c.id
            JOIN task_types tt ON tl.task_type_id = tt.id
            WHERE tl.id = ?
            """,
            (id,),
        ).fetchone()

        return rows

def update_log(id, log_date, client_id, task_type_id, quantity, notes):
    conn = get_connection()
    with closing(conn):
        conn.execute(
            """
            UPDATE task_logs
            SET log_date = ?,
                client_id = ?, 
                task_type_id = ?, 
                quantity = ?, 
                notes = ?
            WHERE id = ?
            """,
            (log_date, client_id, task_type_id, quantity, notes, id),
        )
        conn.commit()

if __name__ == '__main__':
    print(get_log(2).keys())