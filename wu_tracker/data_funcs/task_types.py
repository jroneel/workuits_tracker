from contextlib import closing
import sqlite3

from wu_tracker.data_funcs.get_connection import get_connection

def get_task_type_by_id(id)->sqlite3.Row:
    """Get a task_type object by id number"""
    conn = get_connection()

    with closing(conn):
        row = conn.execute(
            """
            SELECT * FROM task_types
            WHERE id = ?
            """, (id,)).fetchone()
        
        return row
    
def get_all_task_types()->sqlite3.Row:
    """Get all task_types objects"""
    conn = get_connection()

    with closing(conn):
        row = conn.execute(
            """
            SELECT * FROM task_types
            """).fetchall()
        
        return row