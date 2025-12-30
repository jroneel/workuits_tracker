from contextlib import closing
import sqlite3

from wu_tracker.data_funcs.get_connection import get_connection

def get_client_by_id(id)->sqlite3.Row:
    """Get a client object by id number"""
    conn = get_connection()

    with closing(conn):
        row = conn.execute(
            """
            SELECT * FROM clients
            WHERE id = ?
            """, (id,)).fetchone()
        
        return row
    
def get_all_clients()->sqlite3.Row:
    """Get all clients objects"""
    conn = get_connection()

    with closing(conn):
        row = conn.execute(
            """
            SELECT * FROM clients
            """).fetchall()
        
        return row