from contextlib import closing
import streamlit as st

from wu_tracker.data_funcs.get_connection import get_connection

def update_task(task_log_id, task_type_id, quantity, wu_per_unit, notes):
    conn = get_connection()
    with closing(conn):
        conn.execute(
            """UPDATE task_log 
            SET (task_type_id = ?, quantity = ?, wu_total = ?, notes = ?_
            WHERE id = ?;""",
            (task_type_id, quantity, wu_per_unit*quantity, notes, task_log_id),
        )
        conn.commit()