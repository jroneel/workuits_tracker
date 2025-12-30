import streamlit as st
import sqlite3
from datetime import date, datetime, timedelta
import pandas as pd
from contextlib import closing
import os
import hashlib
import secrets

from wu_tracker.data_funcs.update_task import update_task
from wu_tracker.widgets.edit_log import edit_log

DB_PATH = "backoffice.db"

# ---------- PASSWORD HASHING ----------

def hash_password(password: str, salt: str | None = None) -> str:
    """
    Returns 'salt$hash' string.
    Not production-grade, but better than plain text.
    """
    if salt is None:
        salt = os.urandom(16).hex()
    pw_bytes = (salt + password).encode("utf-8")
    digest = hashlib.sha256(pw_bytes).hexdigest()
    return f"{salt}${digest}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt, stored_hash = stored.split("$", 1)
    except ValueError:
        return False
    pw_bytes = (salt + password).encode("utf-8")
    digest = hashlib.sha256(pw_bytes).hexdigest()
    return digest == stored_hash


# ---------- DB HELPERS ----------

def init_db():
    with closing(sqlite3.connect(DB_PATH)) as conn:
        c = conn.cursor()

        # Users table
        c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            full_name TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0
        );
        """)

        # Clients
        c.execute("""
        CREATE TABLE IF NOT EXISTS clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            monthly_rate REAL NOT NULL DEFAULT 0,
            active INTEGER NOT NULL DEFAULT 1
        );
        """)

        # Task types (each has WU per unit)
        c.execute("""
        CREATE TABLE IF NOT EXISTS task_types (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            description TEXT,
            wu_per_unit REAL NOT NULL
        );
        """)

        # Task logs
        c.execute("""
        CREATE TABLE IF NOT EXISTS task_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            log_date TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            employee_name TEXT NOT NULL,
            employee_id INTEGER,
            client_id INTEGER NOT NULL,
            task_type_id INTEGER NOT NULL,
            quantity REAL NOT NULL,
            wu_total REAL NOT NULL,
            notes TEXT,
            FOREIGN KEY (client_id) REFERENCES clients(id),
            FOREIGN KEY (task_type_id) REFERENCES task_types(id),
            FOREIGN KEY (employee_id) REFERENCES users(id)
        );
        """)

        # Client blockers: items waiting on client deliverables
        c.execute("""
        CREATE TABLE IF NOT EXISTS client_blockers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            details TEXT,
            requested_at TEXT NOT NULL,
            due_date TEXT,
            status TEXT NOT NULL DEFAULT 'open',  -- 'open' or 'resolved'
            resolved_at TEXT,
            created_by INTEGER,
            FOREIGN KEY (client_id) REFERENCES clients(id),
            FOREIGN KEY (created_by) REFERENCES users(id)
        );
        """)


        conn.commit()


def get_connection():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


# ---------- USERS / AUTH ----------

def get_user_by_username(username: str):
    conn = get_connection()
    with closing(conn):
        row = conn.execute(
            "SELECT * FROM users WHERE username = ?;",
            (username,),
        ).fetchone()
    return row


def get_all_users():
    conn = get_connection()
    with closing(conn):
        rows = conn.execute("SELECT id, username, full_name, is_admin FROM users ORDER BY username;").fetchall()
    return rows


def get_admin_count() -> int:
    conn = get_connection()
    with closing(conn):
        row = conn.execute("SELECT COUNT(*) AS cnt FROM users WHERE is_admin = 1;").fetchone()
    return row["cnt"] if row else 0


def delete_user(user_id: int):
    # Prevent deleting the last admin
    conn = get_connection()
    with closing(conn):
        is_admin_row = conn.execute("SELECT is_admin FROM users WHERE id = ?;", (user_id,)).fetchone()
        if is_admin_row and is_admin_row["is_admin"]:
            admin_count = conn.execute("SELECT COUNT(*) AS cnt FROM users WHERE is_admin = 1;").fetchone()["cnt"]
            if admin_count <= 1:
                raise ValueError("Cannot delete the last admin user.")

        conn.execute("DELETE FROM users WHERE id = ?;", (user_id,))
        conn.commit()


def update_user(user_id: int, username: str, full_name: str, is_admin: int):
    # Prevent demoting last admin
    conn = get_connection()
    with closing(conn):
        cur = conn.execute("SELECT is_admin FROM users WHERE id = ?;", (user_id,)).fetchone()
        if cur and cur["is_admin"] and not is_admin:
            admin_count = conn.execute("SELECT COUNT(*) AS cnt FROM users WHERE is_admin = 1;").fetchone()["cnt"]
            if admin_count <= 1:
                raise ValueError("Cannot remove admin privileges from the last admin user.")

        conn.execute(
            "UPDATE users SET username = ?, full_name = ?, is_admin = ? WHERE id = ?;",
            (username, full_name, int(is_admin), user_id),
        )
        conn.commit()


def reset_user_password(user_id: int, new_password: str | None = None) -> str:
    # If new_password is None, generate a temporary password and return it
    if new_password is None:
        new_password = secrets.token_urlsafe(10)
    pw_hash = hash_password(new_password)
    conn = get_connection()
    with closing(conn):
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?;", (pw_hash, user_id))
        conn.commit()
    return new_password


def get_users_count() -> int:
    conn = get_connection()
    with closing(conn):
        row = conn.execute("SELECT COUNT(*) AS cnt FROM users;").fetchone()
    return row["cnt"] if row else 0


def create_user(username: str, full_name: str, password: str):
    """
    First user created becomes admin; others are normal users.
    """
    existing_count = get_users_count()
    is_admin = 1 if existing_count == 0 else 0
    password_hash = hash_password(password)

    conn = get_connection()
    with closing(conn):
        conn.execute(
            """
            INSERT INTO users (username, full_name, password_hash, is_admin)
            VALUES (?, ?, ?, ?);
            """,
            (username, full_name, password_hash, is_admin),
        )
        conn.commit()


# ---------- BUSINESS DATA ACCESS ----------

def get_clients(active_only=True):
    conn = get_connection()
    with closing(conn):
        if active_only:
            rows = conn.execute(
                "SELECT * FROM clients WHERE active = 1 ORDER BY name;"
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM clients ORDER BY active DESC, name;"
            ).fetchall()
    return rows


def add_client(name, monthly_rate):
    conn = get_connection()
    with closing(conn):
        conn.execute(
            "INSERT OR IGNORE INTO clients (name, monthly_rate, active) VALUES (?, ?, 1);",
            (name, monthly_rate),
        )
        conn.commit()


def update_client_rate(client_id, monthly_rate, active=True):
    conn = get_connection()
    with closing(conn):
        conn.execute(
            "UPDATE clients SET monthly_rate = ?, active = ? WHERE id = ?;",
            (monthly_rate, int(active), client_id),
        )
        conn.commit()


def get_task_types():
    conn = get_connection()
    with closing(conn):
        rows = conn.execute(
            "SELECT * FROM task_types ORDER BY name;"
        ).fetchall()
    return rows


def add_task_type(name, description, wu_per_unit):
    conn = get_connection()
    with closing(conn):
        conn.execute(
            "INSERT OR IGNORE INTO task_types (name, description, wu_per_unit) VALUES (?, ?, ?);",
            (name, description, wu_per_unit),
        )
        conn.commit()


def update_task_type(task_type_id, wu_per_unit):
    conn = get_connection()
    with closing(conn):
        conn.execute(
            "UPDATE task_types SET wu_per_unit = ? WHERE id = ?;",
            (wu_per_unit, task_type_id),
        )
        conn.commit()


def insert_task_log(log_date, employee_name, employee_id, client_id, task_type_id, quantity, wu_total, notes):
    conn = get_connection()
    with closing(conn):
        conn.execute(
            """
            INSERT INTO task_logs (
                log_date, employee_name, employee_id, client_id,
                task_type_id, quantity, wu_total, notes
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (log_date, employee_name, employee_id, client_id, task_type_id, quantity, wu_total, notes),
        )
        conn.commit()

def get_recent_logs(limit=20, employee_id=None):
    conn = get_connection()
    with closing(conn):
        if employee_id is not None:
            rows = conn.execute(
                """
                SELECT tl.*, c.name AS client_name, tt.name AS task_type_name
                FROM task_logs tl
                JOIN clients c ON tl.client_id = c.id
                JOIN task_types tt ON tl.task_type_id = tt.id
                WHERE tl.employee_id = ?
                ORDER BY tl.created_at DESC
                LIMIT ?;
                """,
                (employee_id, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT tl.*, c.name AS client_name, tt.name AS task_type_name
                FROM task_logs tl
                JOIN clients c ON tl.client_id = c.id
                JOIN task_types tt ON tl.task_type_id = tt.id
                ORDER BY tl.created_at DESC
                LIMIT ?;
                """,
                (limit,),
            ).fetchall()
    return rows


def get_logs_by_timeframe(start:datetime|str, end=None):
    
    if isinstance(start, datetime):
        start = start.strftime('%Y-%m-%d %H:%M:%S')
    
    conn = get_connection()
    with closing(conn):
        stmt = (
            f"""
            SELECT tl.*, c.name AS client_name, tt.name AS task_type_name
            FROM task_logs tl
            JOIN users ON tl.employee_id = users.id
            JOIN clients c ON tl.client_id = c.id
            JOIN task_types tt ON tl.task_type_id = tt.id
            WHERE tl.log_date > '{start}'
            ORDER BY tl.created_at DESC
            """)
        df = pd.read_sql(stmt, conn)
    
    return df

def get_aggregated_wu(start_date=None, end_date=None, client_id=None):
    conn = get_connection()
    base_query = """
        SELECT
            c.name AS client_name,
            strftime('%Y-%m', tl.log_date) AS ym,
            SUM(tl.wu_total) AS total_wu,
            c.monthly_rate
        FROM task_logs tl
        JOIN clients c ON tl.client_id = c.id
        WHERE 1=1
    """
    params = []

    if start_date:
        base_query += " AND date(tl.log_date) >= date(?)"
        params.append(start_date)
    if end_date:
        base_query += " AND date(tl.log_date) <= date(?)"
        params.append(end_date)
    if client_id:
        base_query += " AND tl.client_id = ?"
        params.append(client_id)

    base_query += """
        GROUP BY c.id, ym
        ORDER BY c.name, ym;
    """

    with closing(conn):
        df = pd.read_sql_query(base_query, conn, params=params)
    if not df.empty:
        df["rate_per_wu"] = df.apply(
            lambda r: (r["monthly_rate"] / r["total_wu"]) if r["total_wu"] else None,
            axis=1,
        )
    return df

def create_client_blocker(client_id, title, details, requested_at, due_date, created_by):
    conn = get_connection()
    with closing(conn):
        conn.execute(
            """
            INSERT INTO client_blockers (
                client_id, title, details,
                requested_at, due_date,
                status, created_by
            )
            VALUES (?, ?, ?, ?, ?, 'open', ?);
            """,
            (
                client_id,
                title,
                details,
                requested_at,
                due_date,
                created_by,
            ),
        )
        conn.commit()


def get_open_blockers():
    conn = get_connection()
    with closing(conn):
        rows = conn.execute(
            """
            SELECT cb.*, c.name AS client_name, u.full_name AS created_by_name
            FROM client_blockers cb
            JOIN clients c ON cb.client_id = c.id
            LEFT JOIN users u ON cb.created_by = u.id
            WHERE cb.status = 'open'
            ORDER BY c.name, cb.requested_at ASC;
            """
        ).fetchall()
    return rows


def get_resolved_blockers(limit=50):
    conn = get_connection()
    with closing(conn):
        rows = conn.execute(
            """
            SELECT cb.*, c.name AS client_name, u.full_name AS created_by_name
            FROM client_blockers cb
            JOIN clients c ON cb.client_id = c.id
            LEFT JOIN users u ON cb.created_by = u.id
            WHERE cb.status = 'resolved'
            ORDER BY cb.resolved_at DESC
            LIMIT ?;
            """,
            (limit,),
        ).fetchall()
    return rows


def resolve_blocker(blocker_id):
    conn = get_connection()
    with closing(conn):
        conn.execute(
            """
            UPDATE client_blockers
            SET status = 'resolved',
                resolved_at = datetime('now')
            WHERE id = ?;
            """,
            (blocker_id,),
        )
        conn.commit()

def create_client_blocker(client_id, title, details, requested_at, due_date, created_by):
    conn = get_connection()
    with closing(conn):
        conn.execute(
            """
            INSERT INTO client_blockers (
                client_id, title, details,
                requested_at, due_date,
                status, created_by
            )
            VALUES (?, ?, ?, ?, ?, 'open', ?);
            """,
            (
                client_id,
                title,
                details,
                requested_at,
                due_date,
                created_by,
            ),
        )
        conn.commit()


def get_open_blockers():
    conn = get_connection()
    with closing(conn):
        rows = conn.execute(
            """
            SELECT cb.*, c.name AS client_name, u.full_name AS created_by_name
            FROM client_blockers cb
            JOIN clients c ON cb.client_id = c.id
            LEFT JOIN users u ON cb.created_by = u.id
            WHERE cb.status = 'open'
            ORDER BY c.name, cb.requested_at ASC;
            """
        ).fetchall()
    return rows


def get_resolved_blockers(limit=50):
    conn = get_connection()
    with closing(conn):
        rows = conn.execute(
            """
            SELECT cb.*, c.name AS client_name, u.full_name AS created_by_name
            FROM client_blockers cb
            JOIN clients c ON cb.client_id = c.id
            LEFT JOIN users u ON cb.created_by = u.id
            WHERE cb.status = 'resolved'
            ORDER BY cb.resolved_at DESC
            LIMIT ?;
            """,
            (limit,),
        ).fetchall()
    return rows


def resolve_blocker(blocker_id):
    conn = get_connection()
    with closing(conn):
        conn.execute(
            """
            UPDATE client_blockers
            SET status = 'resolved',
                resolved_at = datetime('now')
            WHERE id = ?;
            """,
            (blocker_id,),
        )
        conn.commit()

def create_client_blocker(client_id, title, details, requested_at, due_date, created_by):
    conn = get_connection()
    with closing(conn):
        conn.execute(
            """
            INSERT INTO client_blockers (
                client_id, title, details,
                requested_at, due_date,
                status, created_by
            )
            VALUES (?, ?, ?, ?, ?, 'open', ?);
            """,
            (
                client_id,
                title,
                details,
                requested_at,
                due_date,
                created_by,
            ),
        )
        conn.commit()


def get_open_blockers():
    conn = get_connection()
    with closing(conn):
        rows = conn.execute(
            """
            SELECT cb.*, c.name AS client_name, u.full_name AS created_by_name
            FROM client_blockers cb
            JOIN clients c ON cb.client_id = c.id
            LEFT JOIN users u ON cb.created_by = u.id
            WHERE cb.status = 'open'
            ORDER BY c.name, cb.requested_at ASC;
            """
        ).fetchall()
    return rows


def get_resolved_blockers(limit=50):
    conn = get_connection()
    with closing(conn):
        rows = conn.execute(
            """
            SELECT cb.*, c.name AS client_name, u.full_name AS created_by_name
            FROM client_blockers cb
            JOIN clients c ON cb.client_id = c.id
            LEFT JOIN users u ON cb.created_by = u.id
            WHERE cb.status = 'resolved'
            ORDER BY cb.resolved_at DESC
            LIMIT ?;
            """,
            (limit,),
        ).fetchall()
    return rows


def resolve_blocker(blocker_id):
    conn = get_connection()
    with closing(conn):
        conn.execute(
            """
            UPDATE client_blockers
            SET status = 'resolved',
                resolved_at = datetime('now')
            WHERE id = ?;
            """,
            (blocker_id,),
        )
        conn.commit()

def blocks_view(user):
    st.header("Waiting Blocks")

    clients = get_clients(active_only=True)
    if not clients:
        st.warning("No clients configured yet. Ask an admin to add clients first.")
        return

    client_map = {c["name"]: c["id"] for c in clients}

    with st.form("add_blocker_form"):
        client_label = st.selectbox("Client", list(client_map.keys()))
        title = st.text_input(
            "What are you waiting on?",
            placeholder="e.g. March bank statements, updated driver list, signed engagement letter"
        )
        details = st.text_area(
            "Details (optional)",
            placeholder="e.g. Requested via email, they said they would send by Friday."
        )
        requested_date = st.date_input("Requested date", value=date.today())

        submitted = st.form_submit_button("Add waiting block")

        if submitted:
            if not title.strip():
                st.error("Title is required.")
            else:
                client_id = client_map[client_label]
                requested_at_str = datetime.combine(requested_date, datetime.min.time()).isoformat()

                create_client_blocker(
                    client_id=client_id,
                    title=title.strip(),
                    details=details.strip() if details else None,
                    requested_at=requested_at_str,
                    due_date=None,
                    created_by=user["id"],
                )
                st.success("Waiting block added ✅")

    st.subheader("Open waiting blocks")

    open_blocks = get_open_blockers()
    if not open_blocks:
        st.info("No open waiting blocks. 🎉")
    else:
        for b in open_blocks:
            header = f"{b['client_name']} – {b['title']}"
            if b["requested_at"]:
                header += f" (since {str(b['requested_at'])[:10]})"

            with st.expander(header, expanded=False):
                st.write(f"**Client:** {b['client_name']}")
                if b["created_by_name"]:
                    st.write(f"**Created by:** {b['created_by_name']}")
                if b["requested_at"]:
                    st.write(f"**Requested at:** {b['requested_at']}")
                if b["due_date"]:
                    st.write(f"**Desired due date:** {b['due_date']}")
                if b["details"]:
                    st.write("**Details:**")
                    st.write(b["details"])
                if b["resolved_at"]:
                    st.write(f"**Resolved at:** {b['resolved_at']}")

                if st.button("Mark as resolved", key=f"resolve_blocker_{b['id']}"):
                    resolve_blocker(b["id"])
                    st.success("Marked as resolved. It will disappear after the next refresh.")

    st.subheader("Recently resolved blocks")
    resolved_blocks = get_resolved_blockers(limit=20)
    if resolved_blocks:
        df = pd.DataFrame([dict(b) for b in resolved_blocks])
        df_view = df[["resolved_at", "client_name", "title", "requested_at", "due_date", "created_by_name"]]
        df_view.rename(
            columns={
                "resolved_at": "Resolved at",
                "client_name": "Client",
                "title": "Title",
                "requested_at": "Requested at",
                "due_date": "Due date",
                "created_by_name": "Created by",
            },
            inplace=True,
        )
        st.dataframe(df_view, width='stretch')
    else:
        st.caption("No recent resolved blocks yet.")


# ---------- UI: AUTH PAGES ----------

def auth_page():
    st.title("Back Office Workload Tracker")

    mode = st.radio("Welcome! Choose an option:", ["Login", "Sign up"])

    if mode == "Login":
        login_form()
    else:
        signup_form()


def login_form():
    st.subheader("Login")

    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Login")

    if submitted:
        if not username or not password:
            st.error("Please enter both username and password.")
            return

        user = get_user_by_username(username)
        if user is None:
            st.error("Invalid username or password.")
            return

        if not verify_password(password, user["password_hash"]):
            st.error("Invalid username or password.")
            return

        # Login success
        st.session_state["user"] = dict(user)
        st.success(f"Welcome, {user['full_name']}!")


def signup_form():
    st.subheader("Sign up")

    with st.form("signup_form"):
        username = st.text_input("Username (for login)")
        full_name = st.text_input("Your full name (for logs)")
        password = st.text_input("Password", type="password")
        password2 = st.text_input("Confirm password", type="password")
        submitted = st.form_submit_button("Create account")

    if submitted:
        if not username or not full_name or not password:
            st.error("All fields are required.")
            return
        if password != password2:
            st.error("Passwords do not match.")
            return

        if get_user_by_username(username) is not None:
            st.error("Username already exists. Please choose another.")
            return

        try:
            create_user(username.strip(), full_name.strip(), password)
        except Exception as e:
            st.error(f"Error creating user: {e}")
            return

        # Auto-login after signup
        user = get_user_by_username(username.strip())
        st.session_state["user"] = dict(user)
        if user["is_admin"]:
            st.success(f"Account created. {full_name} is the first user and has admin rights.")
        else:
            st.success("Account created and logged in.")


# ---------- UI: EMPLOYEE VIEW ----------

def employee_view(user):
    st.header("Log Work")

    # Use account full_name as employee name
    employee_name = user["full_name"]
    employee_id = user["id"]
    st.info(f"Logging work as **{employee_name}**")

    clients = get_clients(active_only=True)
    if not clients:
        st.warning("No clients configured yet. Ask an admin to add clients first.")
        return

    task_types = get_task_types()
    if not task_types:
        st.warning("No task types configured yet. Ask an admin to add task types first.")
        return

    client_map = {f"{c['name']} (${c['monthly_rate']:.2f}/mo)": c["id"] for c in clients}
    task_map = {f"{t['name']} ({t['wu_per_unit']} WU/unit)": t["id"] for t in task_types}
    task_wu_lookup = {t["id"]: t["wu_per_unit"] for t in task_types}

    with st.form("log_task"):
        col1, col2 = st.columns(2)

        with col1:
            work_date = st.date_input("Date of work", value=date.today())

        with col2:
            work_time = st.time_input("Time of work", value=datetime.now().time().replace(second=0, microsecond=0))

        # Combine into a single datetime object
        log_datetime = datetime.combine(work_date, work_time)
        log_datetime_str = log_datetime.isoformat()

        row2 = st.columns(3)

        with row2[0]:
            client_label = st.selectbox("Client", list(client_map.keys()))
        with row2[1]:
            task_label = st.selectbox("Task type", list(task_map.keys()))
        with row2[2]:
            quantity = st.number_input("Quantity (e.g., 10 transactions, 3 calls)", min_value=0.0, step=1.0, value=1.0)
        
        notes = st.text_area("Notes (optional)", placeholder="e.g. Reconciled 3 accounts and followed up with vendor X.")

        client_id = client_map[client_label]
        task_type_id = task_map[task_label]
        wu_per_unit = task_wu_lookup[task_type_id]
        wu_total = wu_per_unit * quantity

        st.caption(f"Calculated Work Units for this log: **{wu_total:.2f} WU**")


        submitted = st.form_submit_button("Save log")
        if submitted:
            # Insert the work log as before
            insert_task_log(
                log_date=log_datetime_str,  # using date+time combo you set up
                employee_name=employee_name,
                employee_id=employee_id,
                client_id=client_id,
                task_type_id=task_type_id,
                quantity=quantity,
                wu_total=wu_total,
                notes=notes.strip() if notes else None,
            )

            st.success("Task log saved ✅")

    st.subheader("Your recent logs")
    logs = get_recent_logs(employee_id=employee_id, limit=20)
    if logs:
        df = pd.DataFrame([dict(r) for r in logs])
        df_view = df[["created_at", "log_date", "client_name", "task_type_name", "quantity", "wu_total", "notes"]].copy()
        df_view.rename(
            columns={
            "created_at": "Logged at",
            "log_date": "Date",
            "client_name": "Client",
            "task_type_name": "Task",
            "quantity": "Qty",
            "wu_total": "WU",
            "notes": "Notes",
            },
            inplace=True,
        )
        # Render rows with an inline action button for each row
        for _, r in df.iterrows():
            cols = st.columns([4, 1, 1, 1])
            with cols[0]:
                st.write(f"**{r['log_date']}** — {r['client_name']} — {r['task_type_name']}")
                if r.get('notes'):
                    st.caption(r['notes'])
            with cols[1]:
                st.write(f"Qty: {r['quantity']}")
            with cols[2]:
                try:
                    st.write(f"WU: {float(r['wu_total']):.2f}")
                except Exception:
                    st.write(f"WU: {r['wu_total']}")
            with cols[3]:
                st.button("Select", key=f"select_log_{r['id']}", on_click=edit_log, args=[r['id']])
                
                # if st.button("Select", key=f"select_log_{r['id']}"):
                #     st.session_state['selected_log'] = int(r['id'])
                #     st.success(f"Selected log id {r['id']}")
                    
    else:
        st.info("No logs yet. Submit your first one above.")


# ---------- UI: ADMIN TABS ----------

def admin_clients_tab():
    st.subheader("Manage Clients")

    st.markdown("### Add new client")
    with st.form("add_client"):
        name = st.text_input("Client name")
        monthly_rate = st.number_input("Monthly rate ($)", min_value=0.0, step=50.0, value=1000.0)
        submitted = st.form_submit_button("Add client")
        if submitted:
            if not name.strip():
                st.error("Client name is required.")
            else:
                add_client(name.strip(), monthly_rate)
                st.success(f"Client '{name.strip()}' added (or already existed).")

    st.markdown("### Existing clients")
    clients = get_clients(active_only=False)
    if not clients:
        st.info("No clients yet.")
        return

    for c in clients:
        cols = st.columns([3, 2, 1, 1])
        with cols[0]:
            st.write(f"**{c['name']}** (id: {c['id']})")
        with cols[1]:
            new_rate = st.number_input(
                f"Monthly rate for {c['name']}",
                key=f"rate_{c['id']}",
                value=float(c["monthly_rate"]),
                step=50.0,
            )
        with cols[2]:
            active = st.checkbox("Active", value=bool(c["active"]), key=f"active_{c['id']}")
        with cols[3]:
            if st.button("Save", key=f"save_{c['id']}"):
                update_client_rate(c["id"], new_rate, active)
                st.success(f"Updated {c['name']}")


def admin_task_types_tab():
    st.subheader("Manage Task Types & WU")

    st.markdown("### Add new task type")
    with st.form("add_task_type"):
        name = st.text_input("Task name", placeholder="e.g. Reconcile bank account")
        description = st.text_input("Description (optional)", placeholder="e.g. Per account reconciled")
        wu_per_unit = st.number_input("Work Units per unit", min_value=0.0, step=0.5, value=10.0)
        submitted = st.form_submit_button("Add task type")
        if submitted:
            if not name.strip():
                st.error("Task name is required.")
            else:
                add_task_type(name.strip(), description.strip() if description else None, wu_per_unit)
                st.success(f"Task type '{name.strip()}' added (or already existed).")

    st.markdown("### Existing task types")
    task_types = get_task_types()
    if not task_types:
        st.info("No task types yet.")
        return

    for t in task_types:
        cols = st.columns([3, 2, 1])
        with cols[0]:
            st.write(f"**{t['name']}** (id: {t['id']})")
            if t["description"]:
                st.caption(t["description"])
        with cols[1]:
            new_wu = st.number_input(
                f"WU/unit for {t['name']}",
                key=f"wu_{t['id']}",
                value=float(t["wu_per_unit"]),
                step=0.5,
            )
        with cols[2]:
            if st.button("Save", key=f"save_task_{t['id']}"):
                update_task_type(t["id"], new_wu)
                st.success(f"Updated WU for {t['name']}")


def admin_users_tab():
    st.subheader("Manage Users")

    st.markdown("### Create a new user (admin only)")
    with st.form("create_user_form"):
        username = st.text_input("Username")
        full_name = st.text_input("Full name")
        password = st.text_input("Password", type="password")
        is_admin_flag = st.checkbox("Grant admin privileges", value=False)
        submitted = st.form_submit_button("Create user")

    if submitted:
        if not username.strip() or not full_name.strip() or not password:
            st.error("All fields are required to create a user.")
        elif get_user_by_username(username.strip()) is not None:
            st.error("Username already exists.")
        else:
            try:
                conn_user = get_users_count()  # just to ensure DB exists
                create_user(username.strip(), full_name.strip(), password)
                # if admin flag was requested and the created user is not admin by default, set it
                user = get_user_by_username(username.strip())
                if is_admin_flag and user and not user["is_admin"]:
                    update_user(user["id"], user["username"], user["full_name"], 1)
                st.success("User created.")
            except Exception as e:
                st.error(f"Error creating user: {e}")

    st.markdown("### Existing users")
    users = get_all_users()
    if not users:
        st.info("No users found.")
        return

    for u in users:
        cols = st.columns([2, 3, 1, 1, 1])
        with cols[0]:
            username_val = st.text_input("Username", value=u["username"], key=f"username_{u['id']}")
        with cols[1]:
            full_name_val = st.text_input("Full name", value=u["full_name"], key=f"fullname_{u['id']}")
        with cols[2]:
            is_admin_val = st.checkbox("Admin", value=bool(u["is_admin"]), key=f"isadmin_{u['id']}")
        with cols[3]:
            if st.button("Save", key=f"save_user_{u['id']}"):
                try:
                    update_user(u["id"], username_val.strip(), full_name_val.strip(), int(bool(is_admin_val)))
                    st.success("User updated.")
                except Exception as e:
                    st.error(f"Could not update user: {e}")
        with cols[4]:
            if st.button("Reset password", key=f"reset_pw_{u['id']}"):
                try:
                    new_pw = reset_user_password(u["id"], None)
                    st.success(f"Password reset. Temporary password: {new_pw}")
                except Exception as e:
                    st.error(f"Could not reset password: {e}")

        # Delete control below row to avoid accidental taps
        delete_key = f"delete_user_{u['id']}"
        if st.button("Delete", key=delete_key):
            # ask for confirmation in-place
            confirm = st.checkbox("Confirm delete", key=f"confirm_{u['id']}")
            if confirm:
                try:
                    delete_user(u["id"])
                    st.success("User deleted. Refresh to update list.")
                except Exception as e:
                    st.error(f"Could not delete user: {e}")


def admin_reports_tab():
    st.subheader("Workload & Pricing Reports")

    clients = get_clients(active_only=False)
    client_options = ["All clients"] + [c["name"] for c in clients]
    client_choice = st.selectbox("Client filter", client_options)

    client_id = None
    if client_choice != "All clients":
        client_id = next(c["id"] for c in clients if c["name"] == client_choice)

    col1, col2 = st.columns(2)
    with col1:
        start_date = st.date_input("Start date", value=date(date.today().year, 1, 1))
    with col2:
        end_date = st.date_input("End date", value=date.today())

    df = get_aggregated_wu(
        start_date=start_date.isoformat(),
        end_date=end_date.isoformat(),
        client_id=client_id,
    )

    if df.empty:
        st.info("No logs found for this period.")
        return

    st.markdown("### Summary table (per client, per month)")
    display_df = df.copy()
    display_df.rename(
        columns={
            "client_name": "Client",
            "ym": "Year-Month",
            "total_wu": "Total WU",
            "monthly_rate": "Monthly rate",
            "rate_per_wu": "Rate per WU ($/WU)",
        },
        inplace=True,
    )
    st.dataframe(display_df, width='stretch')

    st.markdown("### WU by month (selected filter)")
    chart_df = display_df[["Year-Month", "Client", "Total WU"]].set_index("Year-Month")
    st.bar_chart(chart_df)

    st.markdown("### Interpretation helpers")
    st.write("- **Total WU** ↑ while **Monthly rate** stays flat → margin squeeze.")
    st.write("- **Rate per WU** dropping below your target (e.g., $X/WU) → time to consider a rate increase.")

    st.markdown("### Open items waiting on clients")

    blockers = get_open_blockers()
    if not blockers:
        st.info("No open client-dependent items. 🎉")
        return

    # Show each blocker as an expandable card with a resolve button
    for b in blockers:
        header = f"{b['client_name']} – {b['title']}"
        if b["requested_at"]:
            header += f" (since {str(b['requested_at'])[:10]})"

        with st.expander(header, expanded=False):
            st.write(f"**Client:** {b['client_name']}")
            if b["created_by_name"]:
                st.write(f"**Created by:** {b['created_by_name']}")
            st.write(f"**Status:** {b['status']}")
            st.write(f"**Requested at:** {b['requested_at']}")
            if b["due_date"]:
                st.write(f"**Due date:** {b['due_date']}")
            if b["details"]:
                st.write("**Details:**")
                st.write(b["details"])
            if b["followup_count"] is not None and b["followup_count"] > 0:
                st.write(f"**Follow-ups:** {b['followup_count']} (last: {b['last_followup_at']})")

            if st.button("Mark as resolved", key=f"resolve_blocker_{b['id']}"):
                resolve_blocker(b["id"])
                st.success("Marked as resolved. It will disappear after the next refresh.")

def admin_logs_tab():
    st.subheader("All Logged Tasks")
    
    columns = st.columns(3)
    
    with columns[0]:
        logs_since_dt = st.datetime_input(
            "Logs Since", 
            value=datetime.now()-timedelta(weeks=2), 
            key='logs_since_dt',
            )
    logs = get_logs_by_timeframe(logs_since_dt)
    
    if not logs.empty:
        logs.rename(
            columns={
            "created_at": "Logged at",
            "log_date": "Date",
            "client_name": "Client",
            "task_type_name": "Task",
            "quantity": "Qty",
            "wu_total": "WU",
            "notes": "Notes",
            },
            inplace=True,
        )
        # Render rows with an inline action button for each row
        for _, r in logs.iterrows():
            cols = st.columns([3, 2,  1, 1, 1])
            with cols[0]:
                st.write(f"**{r['Date']}** — {r['Client']} — {r['Task']}")
                if r.get('Notes'):
                    st.caption(r['Notes'])
            with cols[1]:
                st.write(f"{r['employee_name']}")
            with cols[2]:
                st.write(f"Qty: {r['Qty']}")
            with cols[3]:
                try:
                    st.write(f"WU: {float(r['WU']):.2f}")
                except Exception:
                    st.write(f"WU: {r['WU']}")
            with cols[4]:
                st.button("Select", key=f"select_log_{r['id']}", on_click=edit_log, args=[r['id']])

def admin_leaderboard():
    st.subheader("Weekly Leaderboard")

    columns = st.columns(3)
    
    with columns[0]:
        leaderboard_ww = st.number_input(
            "Select Workweek", 
            value=int((datetime.now().strftime('%G%V'))),
            min_value=202501,
            max_value=int((datetime.now().strftime('%G%V'))),
            key='leaderboard_ww',
            )
    
    leaderboard_dt = datetime.strptime(str(leaderboard_ww)+'0', '%G%V%w')
    
    logs = get_logs_by_timeframe(start=leaderboard_dt,
                                 end=leaderboard_dt+timedelta(days=7))
    
    logs = logs[['employee_name', 'log_date', 'client_name', 'task_type_name', 'notes', 'wu_total']]

    logs.rename({'employee_name': 'Employee',
                'log_date': 'Date',
                'client_name': 'Client',
                'task_type_name': 'Task',
                'wu_total': 'Total WU',
                'notes': 'Notes'})
    
    st.dataframe(logs)

def admin_view(user):
    st.header("Admin – Configuration & Reporting")

    if not user.get("is_admin"):
        st.error("You do not have admin permissions.")
        return

    tabs = st.tabs(["Users", "Clients", "Task Types & WU", "Reports", "All Logs",
                    "Leaderboard"])

    with tabs[0]:
        admin_users_tab()
    with tabs[1]:
        admin_clients_tab()
    with tabs[2]:
        admin_task_types_tab()
    with tabs[3]:
        admin_reports_tab()
    with tabs[4]:
        admin_logs_tab()
    with tabs[5]:
        admin_leaderboard()


# ---------- MAIN APP ----------

def main():
    st.set_page_config(page_title="Back Office Workload Tracker", layout="wide")
    init_db()

    # Sidebar user info / logout
    user = st.session_state.get("user")
    with st.sidebar:
        st.title("Back Office Tracker")

        if user:
            st.write(f"Logged in as **{user['full_name']}**")
            if user.get("is_admin"):
                st.caption("Role: Admin")
            else:
                st.caption("Role: Employee")

            if st.button("Logout"):
                st.session_state.pop("user", None)
        else:
            st.info("Not logged in")

    # If not logged in, show auth page only
    if not user:
        auth_page()
        return

    # Once logged in: choose role view
    # Non-admin users only see Employee mode; admins can toggle.
    if user.get("is_admin"):
        mode = st.sidebar.radio(
            "Choose view",
            [
                "Log Tasks",
                "Waiting Blocks",
                "Admin",
            ],
        )
    else:
        mode = st.sidebar.radio(
            "Choose view",
            [
                "Log Tasks",
                "Waiting Blocks",
            ],
        )

    if mode.startswith("Log Tasks"):
        employee_view(user)
    elif mode.startswith("Waiting Blocks"):
        blocks_view(user)
    else:
        admin_view(user)


if __name__ == "__main__":
    main()
