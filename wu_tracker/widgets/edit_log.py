import streamlit as st
from contextlib import closing
from datetime import datetime as _dt, datetime

from wu_tracker.data_funcs.get_connection import get_connection
from wu_tracker.data_funcs.logs import get_log, update_log
from wu_tracker.data_funcs.clients import get_all_clients, get_client_by_id
from wu_tracker.data_funcs.task_types import get_all_task_types, get_task_type_by_id

@st.dialog("Edit Log")
def edit_log(log_id):
    """A function to edit a log"""
    st.text(log_id)
    log = get_log(log_id)

    # Default client selection
    current_client = get_client_by_id(log['client_id'])['name']
    clients = {client['name']: client['id'] for client in get_all_clients()}
    default_client_index = list(clients.keys()).index(current_client)

    # Default Task Type selection
    current_task_type = get_task_type_by_id(log['task_type_id'])['name']
    task_types = {task_type['name']: task_type['id'] for task_type in get_all_task_types()}
    default_task_type_index = list(task_types.keys()).index(current_task_type)

    with st.form("log_form"):
        # fields to edit
        client = st.selectbox("Client", options=clients.keys(), index=default_client_index)
        log_date = st.date_input("Date", value=_dt.fromisoformat(log['log_date']).date() if isinstance(log['log_date'], str) else log['log_date'])
        task_type = st.selectbox("Task Type", options=task_types.keys(), index=default_task_type_index)
        quantity = st.number_input("Quantity", value=float(log['quantity'] or 0.0), step=1.0)
        notes = st.text_input("Notes", value=log['notes'] or "")

        if st.form_submit_button("Update Log"):
            update_log(
                log_id, 
                log_date,
                int(clients[client]),
                int(task_types[task_type]),
                float(quantity),
                notes)
            
            st.rerun()