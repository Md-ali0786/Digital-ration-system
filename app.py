from flask import (
    Flask, request, redirect, session, render_template_string,
    g, url_for, flash, send_from_directory
)
from flask_bcrypt import Bcrypt
import sqlite3
import datetime
from functools import wraps
import uuid
import os
import re
import json # New import for passing structured data to JS

# ============================================================
# APP INITIALIZATION
# ============================================================

app = Flask(__name__, static_folder='static')
# IMPORTANT: Replace with a strong, random key in production
app.secret_key = "a-truly-secure-fabolues-ration-system-key-for-project-v10"
bcrypt = Bcrypt(app)

# Directories
BASE_DIR = os.path.dirname(__file__)
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)
STATIC_DIR = os.path.join(BASE_DIR, "static")
os.makedirs(STATIC_DIR, exist_ok=True)

# ============================================================
# DATABASE CONNECTION MANAGEMENT & CONFIG HELPERS
# ============================================================

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(
            os.path.join(BASE_DIR, "ration.db"),
            detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES
        )
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def get_config(key, default=None):
    db = get_db()
    res = db.execute('SELECT value FROM system_config WHERE key = ?', (key,)).fetchone()
    return res['value'] if res else default

def set_config(key, value):
    db = get_db()
    db.execute("INSERT OR REPLACE INTO system_config (key, value) VALUES (?, ?)", (key, str(value)))
    db.commit()

def column_exists(db, table, column):
    info = db.execute(f"PRAGMA table_info({table})").fetchall()
    return any(col['name'] == column for col in info)

def init_db():
    """Initializes the database schema and default admin/items/slots/config, with safe migrations."""
    db = get_db()
    cur = db.cursor()

    # 1. Users Table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            card_number TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            address TEXT,
            photo_filename TEXT,
            card_type TEXT,
            mobile_number TEXT,
            member_count INTEGER NOT NULL DEFAULT 1,
            password_hash TEXT,
            is_admin INTEGER NOT NULL DEFAULT 0,
            is_secondary_admin INTEGER NOT NULL DEFAULT 0,
            is_pre_registered INTEGER NOT NULL DEFAULT 1,
            is_approved INTEGER NOT NULL DEFAULT 0,
            is_blocked INTEGER NOT NULL DEFAULT 0,
            policy_accepted INTEGER NOT NULL DEFAULT 0,
            monthly_collected_kg_rice REAL NOT NULL DEFAULT 0.0,
            monthly_collected_kg_wheat REAL NOT NULL DEFAULT 0.0
        )
    """)
    # Add last_activity_date column for new dashboard feature
    if not column_exists(db, "users", "last_activity_date"):
        cur.execute("ALTER TABLE users ADD COLUMN last_activity_date TEXT")
    
    # Users migrations
    migrations = [
        ("users", "member_count", "ALTER TABLE users ADD COLUMN member_count INTEGER NOT NULL DEFAULT 1"),
        ("users", "photo_filename", "ALTER TABLE users ADD COLUMN photo_filename TEXT"),
        ("users", "monthly_collected_kg_rice", "ALTER TABLE users ADD COLUMN monthly_collected_kg_rice REAL NOT NULL DEFAULT 0.0"),
        ("users", "monthly_collected_kg_wheat", "ALTER TABLE users ADD COLUMN monthly_collected_kg_wheat REAL NOT NULL DEFAULT 0.0"),
        ("users", "policy_accepted", "ALTER TABLE users ADD COLUMN policy_accepted INTEGER NOT NULL DEFAULT 0"),
        ("users", "is_pre_registered", "ALTER TABLE users ADD COLUMN is_pre_registered INTEGER NOT NULL DEFAULT 1"),
        ("users", "is_approved", "ALTER TABLE users ADD COLUMN is_approved INTEGER NOT NULL DEFAULT 0"),
        ("users", "is_blocked", "ALTER TABLE users ADD COLUMN is_blocked INTEGER NOT NULL DEFAULT 0"),
        ("users", "is_secondary_admin", "ALTER TABLE users ADD COLUMN is_secondary_admin INTEGER NOT NULL DEFAULT 0"),
    ]
    for table, column, sql in migrations:
        if not column_exists(db, table, column):
            cur.execute(sql)
            
    cur.execute("CREATE INDEX IF NOT EXISTS idx_users_card_number_password ON users (card_number, password_hash)")

    # 2. Items Table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS items (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            stock REAL NOT NULL,
            unit_price REAL NOT NULL,
            free_limit_kg REAL NOT NULL DEFAULT 0,
            unit TEXT NOT NULL
        )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_items_name ON items (name)")

    # 3. Slots Table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS slots (
            id INTEGER PRIMARY KEY,
            date_time TEXT NOT NULL UNIQUE,
            capacity INTEGER NOT NULL,
            booked_count INTEGER NOT NULL DEFAULT 0
        )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_slots_datetime ON slots (date_time)")

    # 4. Orders Table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY,
            card_number TEXT NOT NULL,
            slot_id INTEGER,
            item_name TEXT NOT NULL,
            quantity REAL NOT NULL,
            is_paid INTEGER NOT NULL DEFAULT 0,
            total_cost REAL NOT NULL,
            order_date TEXT NOT NULL,
            token TEXT NOT NULL,
            free_qty REAL NOT NULL DEFAULT 0.0,
            paid_qty REAL NOT NULL DEFAULT 0.0,
            FOREIGN KEY (card_number) REFERENCES users(card_number),
            FOREIGN KEY (slot_id) REFERENCES slots(id)
        )
    """)

    order_migrations = [
        ("orders", "free_qty", "ALTER TABLE orders ADD COLUMN free_qty REAL NOT NULL DEFAULT 0.0"),
        ("orders", "paid_qty", "ALTER TABLE orders ADD COLUMN paid_qty REAL NOT NULL DEFAULT 0.0"),
    ]
    for table, column, sql in order_migrations:
        if not column_exists(db, table, column):
            cur.execute(sql)
            
    cur.execute("CREATE INDEX IF NOT EXISTS idx_orders_card_number ON orders (card_number)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_orders_token_paid ON orders (token, is_paid)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_orders_slot_id ON orders (slot_id)")


    # 5. System config Table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS system_config (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    """)

    # Seed admins
    cur.execute("SELECT card_number FROM users WHERE is_admin = 1")
    if not cur.fetchone():
        admin_pass = bcrypt.generate_password_hash("Admin@1").decode('utf-8')
        cur.execute("""
            INSERT INTO users (card_number, name, password_hash, is_admin, is_pre_registered, is_approved, policy_accepted, member_count)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, ('admin', 'Main Admin', admin_pass, 1, 0, 1, 1, 1))
        
        view_pass = bcrypt.generate_password_hash("View@123").decode('utf-8')
        cur.execute("""
            INSERT INTO users (card_number, name, password_hash, is_secondary_admin, is_pre_registered, is_approved, policy_accepted, member_count)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, ('view', 'Secondary Admin', view_pass, 0, 0, 1, 1, 1))
        
        # --- ADD WORKING BENEFICIARY ---
        user_pass = bcrypt.generate_password_hash("User@123").decode('utf-8')
        cur.execute("""
            INSERT INTO users (card_number, name, password_hash, is_pre_registered, is_approved, policy_accepted, member_count, card_type, last_activity_date)
            VALUES (?, ?, ?, 1, 1, 1, 4, 'BPL', ?)
        """, ('123456789012', 'Test Beneficiary', user_pass, datetime.datetime.now().isoformat())) 
        # --- END OF FIX ---

    # Seed items
    cur.execute("SELECT id FROM items")
    if not cur.fetchone():
        # Ensure high initial stock for testing
        items = [
            ('Rice', 100000, 0.0, 30, 'kg'),  
            ('Wheat', 80000, 10.0, 25, 'kg'),
            ('Dal', 5000, 15.0, 0, 'kg'),
            ('Oil', 6000, 10.0, 0, 'Litre'),
            ('Soap', 20000, 15.0, 0, 'pc'),
            ('Salt', 15000, 20.0, 0, 'kg'),
        ]
        cur.executemany("""
            INSERT INTO items (name, stock, unit_price, free_limit_kg, unit)
            VALUES (?, ?, ?, ?, ?)
        """, items)

    # Seed config - SYSTEM_FREEZE IS SET TO '0' (UNFROZEN) HERE
    configs = [
        ('system_freeze', '0'),  
        ('max_free_rice_kg', '30'),
        ('max_free_wheat_kg', '25'),
        ('last_reset_date', datetime.date.today().strftime('%Y-%m')),
        ('max_household_size', '10'),
    ]
    cur.executemany("INSERT OR IGNORE INTO system_config (key, value) VALUES (?, ?)", configs)

    # Seed slots (tomorrow 10:00, 11:00, 12:00)
    cur.execute("SELECT id FROM slots")
    if not cur.fetchone():
        tomorrow = datetime.date.today() + datetime.timedelta(days=1)
        for hour in (10, 11, 12):
            dt = datetime.datetime(tomorrow.year, tomorrow.month, tomorrow.day, hour, 0, 0)
            cur.execute("INSERT INTO slots (date_time, capacity) VALUES (?, ?)", (dt.strftime('%Y-%m-%d %H:%M:%S'), 10))

    db.commit()

with app.app_context():
    init_db()

# ============================================================
# AUTH HELPERS  
# ============================================================

def get_user_data():
    if 'user_id' in session:
        db = get_db()
        g.user = db.execute(
            'SELECT * FROM users WHERE card_number = ?', (session['user_id'],)
        ).fetchone()
        return True
    g.user = None
    return False

@app.before_request
def load_logged_in_user():
    get_user_data()
    auto_monthly_reset()

# Helper to update user activity timestamp
def update_user_activity(card_number, activity_type):
    db = get_db()
    now = datetime.datetime.now().isoformat()
    try:
        db.execute("UPDATE users SET last_activity_date = ? WHERE card_number = ?", (now, card_number))
        
        # --- FEATURE: Store Activity Log in Session for Dashboard ---
        activity_log = session.get('activity_log', [])
        # Append new activity (type, timestamp)
        activity_log.insert(0, {'type': activity_type, 'time': now})
        # Keep only the last 5 activities
        session['activity_log'] = activity_log[:5]
        
        db.commit()
    except Exception as e:
        print(f"Error updating activity for {card_number}: {e}") # Log error but continue
        db.rollback()


def login_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        if not get_user_data():
            flash("Login required to access this page.", "error")
            return redirect('/login')
        # Update activity on login required pages
        update_user_activity(g.user['card_number'], 'Page Accessed: ' + request.path.split('/')[-1].replace('_', ' ').title())
        return view(**kwargs)
    return wrapped_view

def admin_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        if not get_user_data() or g.user['is_admin'] != 1:
            flash("Admin permission required.", "error")
            return redirect('/dashboard')
        return view(**kwargs)
    return login_required(wrapped_view)

def secondary_admin_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        if not get_user_data() or (g.user['is_admin'] != 1 and g.user['is_secondary_admin'] != 1):
            flash("Admin or Secondary Admin permission required.", "error")
            return redirect('/dashboard')
        return view(**kwargs)
    return login_required(wrapped_view)

# ============================================================
# Automatic monthly quota reset
# ============================================================

def auto_monthly_reset():
    db = get_db()
    today_key = datetime.date.today().strftime('%Y-%m')
    last = get_config('last_reset_date', '')
    if last != today_key:
        db.execute("""
            UPDATE users
            SET monthly_collected_kg_rice = 0.0,
                monthly_collected_kg_wheat = 0.0
            WHERE is_admin = 0 AND is_secondary_admin = 0
        """)
        set_config('last_reset_date', today_key)

# ============================================================
# FABULOUS HTML/COMPONENT HELPERS
# ============================================================

def render_flashes():
    messages = ""
    flashes = session.pop('_flashes', [])
    for category, msg in flashes:
        color_map = {"error": "red", "success": "green", "warning": "yellow", "info": "blue"}
        color = color_map.get(category, "blue")
        messages += f"<div class='bg-{color}-100 border-l-4 border-{color}-500 text-{color}-800 p-3 mb-4 rounded-lg animate-slide-in' role='alert'>{msg}</div>"
    return messages
    
# --- START FEATURE: Back Button Component (RECONFIRMED) ---
def get_back_button_html():
    """Generates a styled, functional back button using browser history."""
    return f"""
    <div class="mb-4">
        <a href="javascript:history.back()" class="text-blue-600 hover:text-blue-800 font-semibold inline-flex items-center gap-1 transition duration-150">
            <span class="emoji-fix text-lg">⬅️</span> Back
        </a>
    </div>
    """
# --- END FEATURE ---


def get_logo_html():
    return f"""
    <div class="flex items-center gap-1">
        <span class="text-3xl animate-pulse emoji-fix">🇮🇳</span>
        <div class="ml-1">
            <div class="text-white font-extrabold text-2xl tracking-wide">SMART RATION SYSTEM</div>
            <div class="text-teal-200 text-xs font-medium">Digital Distribution Initiative</div>
        </div>
    </div>
    """
    
def get_stat_card(title, value, unit="", color="teal", icon="⭐"):
    return f"""
    <div class="bg-white p-5 rounded-lg shadow-xl border-t-8 border-{color}-500 text-center transform hover:scale-105 transition duration-300">
        <p class="text-5xl mb-2 emoji-fix text-{color}-600">{icon}</p>
        <p class="text-xl font-extrabold text-{color}-800">{value} <span class="text-base font-semibold text-gray-500">{unit}</span></p>
        <p class="text-sm text-gray-500 mt-1 font-semibold">{title}</p>
    </div>
    """

def get_user_initials(user_name):
    """Generates simple initials from a name."""
    if not user_name:
        return '?'
    parts = user_name.split()
    if len(parts) >= 2:
        return (parts[0][0] + parts[-1][0]).upper()
    return user_name[0].upper()

def get_user_photo_display(user):
    """Generates the photo or initial placeholder based on user data for dashboard/profile."""
    if user['photo_filename']:
        # For dashboard/profile display (larger size)
        return f"""
        <img src="{url_for('uploads', filename=user['photo_filename'])}" class="h-16 w-16 rounded-full object-cover mr-4 border-4 border-teal-400" alt="User Photo">
        """
    else:
        initials = get_user_initials(user['name'])
        # Enhanced placeholder with background color
        return f"""
        <div class="h-16 w-16 rounded-full bg-teal-600 flex items-center justify-center text-xl font-bold text-white mr-4 border-4 border-teal-400 shadow-md">
            {initials}
        </div>
        """
# Utility function for date formatting
def format_datetime_since(iso_dt_str):
    if not iso_dt_str: return "N/A"
    try:
        dt = datetime.datetime.fromisoformat(iso_dt_str)
        now = datetime.datetime.now()
        diff = now - dt
        
        if diff.total_seconds() < 60:
            return "just now"
        elif diff.total_seconds() < 3600:
            minutes = int(diff.total_seconds() // 60)
            return f"{minutes} min ago"
        elif diff.total_seconds() < 86400:
            hours = int(diff.total_seconds() // 3600)
            return f"{hours} hours ago"
        else:
            return dt.strftime('%d %b %Y')
    except:
        return "Unknown Date"


def get_admin_sidebar_html(role, is_main_admin):
    active_class = "bg-teal-100 font-bold text-teal-700"
    inactive_class = "hover:bg-teal-50 font-medium text-gray-700"
    
    path = request.path
    
    links = [
        ("Dashboard", "/admin/dashboard", "🏠"),
        ("Pre-register User", "/admin/preregister", "✍"),
        ("Verification / Users", "/admin/manage_users", "👥"),
        ("Manage Stock / Items", "/admin/manage_items", "📦"),
        ("Manage Slots", "/admin/manage_slots", "🗓"),
        ("Reports", "/admin/reports", "📊"),
    ]
    
    admin_links = ""
    for name, route, icon in links:
        is_active = route == path
        admin_links += f"""
        <a href="{route}" class="flex items-center px-3 py-2 rounded text-sm {'bg-teal-600 text-white shadow-md' if is_active else inactive_class}">
            <span class="mr-2 emoji-fix">{icon}</span> {name}
        </a>
        """
        
    special_links = f"""
    <a href="{url_for('admin_token_validation')}" class="flex items-center px-3 py-2 rounded text-sm {'bg-red-700 text-white shadow-lg' if path == '/admin/token_validation' else 'hover:bg-red-50 font-medium text-red-700'}">
        <span class="mr-2 emoji-fix">🔑</span> TOKEN VALIDATION
    </a>
    <a href="{url_for('admin_quota_check')}" class="flex items-center px-3 py-2 rounded text-sm {'bg-purple-600 text-white shadow-lg' if path == '/admin/quota_check' else 'hover:bg-purple-50 font-medium text-purple-700'}">
        <span class="mr-2 emoji-fix">🔍</span> Quota Check
    </a>
    """
    
    # --- START EXTRA FEATURE: Admin Password Change Link ---
    special_links += f"""
    <a href="{url_for('admin_change_password')}" class="flex items-center px-3 py-2 rounded text-sm {'bg-amber-600 text-white shadow-lg' if path == '/admin/change_password' else 'hover:bg-amber-50 font-medium text-amber-700'}">
        <span class="mr-2 emoji-fix">🔒</span> Change Password
    </a>
    """
    # --- END EXTRA FEATURE ---
    
    if is_main_admin:
        special_links += f"""
        <a href="{url_for('admin_manage_secondary_admins')}" class="flex items-center px-3 py-2 rounded text-sm {'bg-yellow-800 text-white shadow-md' if path == '/admin/manage_secondary_admins' else 'hover:bg-yellow-50 font-medium text-yellow-800'}">
            <span class="mr-2 emoji-fix">👑</span> Manage Admins
        </a>
        <a href="{url_for('admin_system_config')}" class="flex items-center px-3 py-2 rounded text-sm {'bg-gray-700 text-white shadow-md' if path == '/admin/system_config' else 'hover:bg-gray-50 font-medium text-gray-700'}">
            <span class="mr-2 emoji-fix">⚙</span> System Config
        </a>
        """

    return f"""
    <div class="w-full md:w-64 bg-white p-4 rounded-xl shadow-2xl border-l-8 border-teal-600 sticky top-24">
        <h3 class="text-xl font-bold mb-4 text-teal-900 border-b pb-2">Control Menu</h3>
        <nav class="space-y-2">
            {admin_links}
            <div class="pt-3 border-t border-gray-200">
                {special_links}
            </div>
        </nav>
    </div>
    """

def get_home_hero_content(db):
    """Generates the hero content with the clock and the static welcome message block (now with transparent style)."""
    
    # --- Live Data ---
    pending_tokens = db.execute("SELECT COUNT(DISTINCT token) FROM orders WHERE is_paid = 0").fetchone()[0] or 0
    total_users = db.execute("SELECT COUNT(*) FROM users WHERE is_admin=0 AND is_secondary_admin=0").fetchone()[0] or 0
    is_frozen = str(get_config('system_freeze', '0')) == '1'
    
    # Static visual switch based on system freeze
    # --- ADJUSTED COLORS FOR ATTRACTIVENESS ---
    switch_class = "bg-red-700 justify-start" if is_frozen else "bg-amber-500 justify-end"
    switch_status = "FREEZE" if is_frozen else "ACTIVE"
    switch_label_class = "text-red-900" if is_frozen else "text-amber-900"
    # --- END ADJUSTED COLORS ---
    
    switch_html = f"""
    <div class="flex items-center">
        <p class="text-sm font-bold {switch_label_class} mr-3">SYSTEM STATUS: {switch_status}</p>
        <div class="w-12 h-6 flex items-center rounded-full p-1 transition-colors duration-300 shadow-inner {switch_class}">
            <div class="bg-white w-4 h-4 rounded-full shadow-md"></div>
        </div>
    </div>
    """

    return f"""
    <div class="flex flex-col items-center justify-center p-6 space-y-8">
        
        <div id="digital-clock" class="text-6xl font-mono font-bold tracking-wider bg-gray-900 text-yellow-400 p-4 rounded-xl shadow-2xl border-4 border-gray-700 w-full max-w-sm text-center">
            --:--:-- <span class="text-2xl block font-normal">--</span>
        </div>

        <div class="glass-container p-6 rounded-3xl shadow-2xl w-full max-w-md border-b-8 border-yellow-400 transform hover:scale-105 transition duration-300 relative overflow-hidden">
            <div class="text-3xl font-extrabold text-yellow-400 mb-3 border-b border-gray-500 pb-2 text-center">
                <span class="emoji-fix">🏠</span> Digital Ration Hub
            </div>
            
            <div class="h-16 flex items-center justify-center text-center">
                <div class="text-xl font-extrabold text-white bg-blue-900/70 p-2 rounded-xl shadow-2xl border-y-4 border-amber-400/80">
                    Welcome to the Smart Ration Distribution Service
                </div>
            </div>
            <div class="mt-4 pt-3 border-t border-gray-500">
                <div class="grid grid-cols-2 gap-4">
                    
                    <div class="p-4 rounded-xl bg-blue-700/60 backdrop-blur-md text-white border border-amber-300/50 shadow-lg">
                        <p class="text-xs font-semibold opacity-80">Total Beneficiaries:</p>
                        <p class="text-3xl font-extrabold text-amber-300">{total_users}</p>
                    </div>

                    <div class="p-4 rounded-xl bg-blue-700/60 backdrop-blur-md text-white border border-amber-300/50 shadow-lg">
                        <p class="text-xs font-semibold opacity-80">Orders Pending:</p>
                        <p class="text-3xl font-extrabold text-red-400">{pending_tokens}</p>
                    </div>
                </div>
                
                <div class="mt-4 flex justify-center bg-blue-900/30 p-2 rounded-xl border border-amber-400/50 shadow-inner">
                    {switch_html}
                </div>
            </div>
        </div>
        
    </div>
    """

def get_layout(title, content, role='guest'):
    
    db = get_db()
    
    # Script for Password Visibility Toggle (for pages using password inputs: login, register, admin_login, admin_edit_user, admin_change_password)
    password_toggle_script = """
    <script>
        function togglePasswordVisibility(fieldId, iconId) {
            const field = document.getElementById(fieldId);
            const icon = document.getElementById(iconId);
            if (field.type === "password") {
                field.type = "text";
                icon.innerHTML = '🙈'; // Eye-slash
            } else {
                field.type = "password";
                icon.innerHTML = '👀'; // Eye
            }
        }
    </script>
    """
    
    user_links = f"""
        <a href="{url_for('dashboard')}" class="px-3 py-2 rounded-md text-sm font-medium hover:underline">Dashboard</a>
        <a href="{url_for('book_items')}" class="px-3 py-2 rounded-md text-sm font-medium hover:underline">Book Items</a>
        <a href="{url_for('history')}" class="px-3 py-2 rounded-md text-sm font-medium hover:underline">Order History</a>
        <a href="{url_for('profile')}" class="px-3 py-2 rounded-md text-sm font-medium hover:underline">Profile</a>
        <a href="{url_for('ration_rules_page')}" class="px-3 py-2 rounded-md text-sm font-medium hover:underline">Ration Rules</a>
        <a href="{url_for('logout')}" class="px-3 py-2 rounded-md text-sm font-medium hover:underline">Logout</a>
    """
    
    admin_nav_links = ""
    if role == 'admin' or role == 'secondary_admin':
        admin_nav_links = f"""
            <a href="{url_for('admin_dashboard')}" class="px-3 py-2 rounded-md text-sm font-medium hover:underline">Admin Dashboard</a>
            <a href="{url_for('admin_manage_users')}" class="px-3 py-2 rounded-md text-sm font-medium hover:underline">Manage Users</a>
            <a href="{url_for('admin_token_validation')}" class="px-3 py-2 rounded-md text-sm font-medium hover:underline bg-red-700 text-white rounded-xl font-bold">TOKEN VALIDATION</a>
            <a href="{url_for('logout')}" class="px-3 py-2 rounded-md text-sm font-medium hover:underline">Logout</a>
        """

    if role == 'user':
        nav_middle = user_links
        nav_right = f'<a href="{url_for('logout')}" class="hidden sm:inline-block bg-white text-red-700 px-4 py-2 rounded-xl font-semibold hover:shadow-lg hover:bg-gray-100">Logout</a>'
    elif role == 'admin' or role == 'secondary_admin':
        nav_middle = admin_nav_links
        nav_right = f'<a href="{url_for('logout')}" class="hidden sm:inline-block bg-white text-red-700 px-4 py-2 rounded-xl font-semibold hover:shadow-lg hover:bg-gray-100">Logout</a>'
    else:
        # Navigation links for guest user (Home link removed from the list)
        nav_middle = f"""
            <a href="{url_for('how_it_works')}" class="px-3 py-2 rounded-md text-sm font-medium hover:underline">How It Works</a>
            <a href="{url_for('ration_rules_page')}" class="px-3 py-2 rounded-md text-sm font-medium hover:underline">Ration Rules</a>
            <a href="{url_for('register')}" class="px-3 py-2 rounded-md text-sm font-medium hover:underline">Register</a>
        """
        nav_right = f"""
            <a href="{url_for('login')}" class="hidden sm:inline-block bg-white text-blue-700 px-4 py-2 rounded-xl font-bold hover:shadow-lg">User Login</a>
            <a href="{url_for('admin_login')}" class="hidden sm:inline-block bg-yellow-400 text-gray-900 px-4 py-2 rounded-xl font-bold hover:shadow-lg">Admin</a>
        """
    
    logo_html = get_logo_html()
    flashes_html = render_flashes()
    main_class = "max-w-6xl mx-auto p-6" if role not in ['guest'] else "mx-auto"
    
    # NEW Hero Content Logic
    hero_content_html = ""
    if role == 'guest' and title == "Welcome to Smart Ration":
        live_status_board = get_home_hero_content(db)
        hero_content_html = f"""
        <header class="gov-hero-gradient text-white py-16 sm:py-24 relative overflow-hidden">
            <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                <div class="grid grid-cols-1 md:grid-cols-2 gap-12 items-center">
                    <div class="text-left animate-slide-in">
                        <p class="text-xl font-medium mb-3">Smart Ration Distribution System</p>
                        <h1 class="text-6xl sm:text-7xl font-extrabold leading-tight shadow-md">Digital Ration Collection</h1>
                        <p class="mt-6 text-xl max-w-xl opacity-90">Book your entitlements, secure a collection slot, and enjoy hassle-free distribution.</p>
                        
                        <div class="h-10 relative overflow-hidden mt-6 max-w-lg">
                            <div class="absolute w-full top-0 left-0 text-2xl font-semibold opacity-0 carousel-item text-yellow-300">✅ Zero Queues.</div>
                            <div class="absolute w-full top-0 left-0 text-2xl font-semibold opacity-0 carousel-item text-yellow-300">🛡️ Transparent Quotas.</div>
                            <div class="absolute w-full top-0 left-0 text-2xl font-semibold opacity-0 carousel-item text-yellow-300">⏰ Book Your Time Slot.</div>
                        </div>

                        <div class="mt-10 flex gap-6 flex-wrap">
                            <a href="{url_for('register')}" class="bg-yellow-400 text-gray-900 px-8 py-4 rounded-xl font-extrabold text-xl sm:text-2xl shadow-2xl hover:bg-yellow-500 transform hover:scale-105 transition duration-300">New Card? REGISTER NOW</a>
                            <a href="{url_for('login')}" class="bg-white text-blue-800 px-8 py-4 rounded-xl font-extrabold text-xl sm:text-2xl shadow-2xl hover:bg-gray-100 transform hover:scale-105 transition duration-300">User LOGIN</a>
                        </div>
                    </div>
                    {live_status_board}
                </div>
            </div>
        </header>
        """
        
    # Check if the back button should be included (almost everywhere except homepage/login/register)
    back_button = ""
    if title not in ["Welcome to Smart Ration", "Login", "Register Beneficiary", "Admin Login"]:
        back_button = get_back_button_html()


    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>{title} | Smart Ration System</title>
        <script src=https://cdn.tailwindcss.com></script>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        
        <link href=https://fonts.googleapis.com/css2?family=Noto+Color+Emoji&display=swap rel="stylesheet">
        <style>
            /* CUSTOM COLORS/PALETTE (Azure/Teal) */
            .gov-nav {{ background: #1e3a8a; }}
            .gov-hero-gradient {{ background: linear-gradient(135deg, #1e3a8a 0%, #06b6d4 100%); }} /* Azure to Cyan/Teal */
            .card-gradient {{ background: linear-gradient(135deg, #061f43 0%, #0c4a6e 100%); }}
            
            /* Glassmorphism Styles */
            .glass-nav {{ backdrop-filter: blur(6px); background: rgba(30, 58, 138, 0.9); }}
            .glass-container {{
                backdrop-filter: blur(8px);
                background: rgba(30, 58, 138, 0.4); /* Transparent Blue */
                border: 1px solid rgba(255, 255, 255, 0.3);
            }}

            /* Aesthetic fixes */
            @keyframes slideIn {{ from {{ opacity: 0; transform: translateY(20px); }} to {{ opacity: 1; transform: translateY(0); }} }}
            .animate-slide-in {{ animation: slideIn 0.5s ease-out; }}
            
            /* Apply the external font for Emojis */
            .emoji-fix {{
                font-family: "Noto Color Emoji", "Segoe UI Emoji", "Apple Color Emoji", "Segoe UI Symbol", "Noto Sans Symbols", sans-serif;
            }}

            /* Carousel styles - Kept for secondary effects */
            @keyframes carousel {{
                0% {{ opacity: 0; transform: translateY(20px); }}
                5% {{ opacity: 1; transform: translateY(0); }}
                28% {{ opacity: 1; transform: translateY(0); }}
                33% {{ opacity: 0; transform: translateY(-20px); }}
                100% {{ opacity: 0; }}
            }}
            .carousel-item {{
                animation: carousel 9s infinite;
            }}
            .carousel-item:nth-child(1) {{ animation-delay: 0s; }}
            .carousel-item:nth-child(2) {{ animation-delay: 3s; }}
            .carousel-item:nth-child(3) {{ animation-delay: 6s; }}
        </style>
    </head>
    <body class="bg-gray-50 min-h-screen font-sans text-gray-800">

        <nav class="glass-nav sticky top-0 z-50">
            <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                <div class="flex items-center justify-between h-20">
                    <div class="flex items-center gap-3">
                        <a href="/" class="flex items-center gap-3">
                            {logo_html}
                        </a>
                    </div>

                    <div class="hidden md:flex items-center gap-6 text-white text-base">
                        {nav_middle}
                    </div>

                    <div class="flex items-center gap-3">
                        {nav_right}
                        <button onclick="document.getElementById('mobile-menu').classList.toggle('hidden')" class="md:hidden text-white">
                            <svg xmlns=http://www.w3.org/2000/svg class="h-8 w-8" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg>
                        </button>
                    </div>
                </div>
            </div>

            <div id="mobile-menu" class="hidden md:hidden bg-blue-900 px-4 py-3">
                <div class="space-y-2 text-white flex flex-col">
                    {nav_middle}
                </div>
            </div>
        </nav>

        {hero_content_html}

        <main class="{main_class} min-h-[60vh] pt-6">
            {back_button}
            <h2 class="text-3xl font-extrabold text-blue-900 mb-6 border-b-4 border-blue-100 pb-2 flex items-center gap-2">
                <span class="emoji-fix">✨</span> {title}
            </h2>
            {flashes_html}
            <div class="mb-8">
                {content}
            </div>
        </main>

        <footer class="bg-gray-900 text-white text-center p-6 mt-12">
            <div class="max-w-7xl mx-auto">
                <div class="mb-2">© {datetime.datetime.now().year} Smart Ration Distribution System | Digital Initiative</div>
                <div class="text-sm opacity-80">For queries, contact the Admin Portal.</div>
            </div>
        </footer>
        
        <script>
            function updateClock() {{
                const now = new Date();
                let hours = now.getHours();
                const minutes = String(now.getMinutes()).padStart(2, '0');
                const seconds = String(now.getSeconds()).padStart(2, '0');
                const ampm = hours >= 12 ? 'PM' : 'AM';
                hours = hours % 12;
                hours = hours ? hours : 12; // the hour '0' should be '12'
                hours = String(hours).padStart(2, '0');
                
                const clockElement = document.getElementById('digital-clock');
                if (clockElement) {{
                    clockElement.innerHTML = hours + ':' + minutes + ':' + seconds + '<span class="text-2xl block font-normal">' + ampm + '</span>';
                }}
            }}
            // Update the clock every second
            setInterval(updateClock, 1000);
            updateClock(); // Initial call
        </script>
        {password_toggle_script}

    </body>
    </html>
    """

# ============================================================
# PUBLIC & AUTH ROUTES
# ============================================================

@app.route("/")
def home():
    db = get_db()
    role = 'guest'
    
    # --- Fictional Stat Cards for Trust - FABULOUS STATS (from the original version) ---
    stats_html = f"""
    <div class="grid grid-cols-1 sm:grid-cols-3 gap-8 mb-16 max-w-7xl mx-auto px-6">
        {get_stat_card("Beneficiaries Registered", "1.2 M", icon="👪", color="blue")}
        {get_stat_card("Daily Collection Slots", "45,000+", icon="🗓️", color="teal")}
        {get_stat_card("Token Fulfillment Rate", "99.8%", icon="🎯", color="yellow")}
    </div>
    """
    
    # --- NEW: Step-by-Step Process Section - ENHANCED UX ---
    process_html = """
    <div class="mb-16 max-w-7xl mx-auto px-6">
        <h3 class="text-4xl font-extrabold text-blue-900 mb-8 text-center border-b pb-4">The 3-Step Digital Collection Process</h3>
        <div class="grid grid-cols-1 md:grid-cols-3 gap-8 text-center">
            <div class="bg-white p-8 rounded-2xl shadow-2xl border-t-8 border-red-500 transform hover:scale-105 transition duration-500">
                <p class="text-7xl mb-4 emoji-fix">📝</p>
                <h4 class="text-2xl font-bold text-red-600 mb-2">1. Register & Verify</h4>
                <p class="text-md text-gray-600">Complete your online registration and await quick government verification. **Secure your login.**</p>
            </div>
            <div class="bg-white p-8 rounded-2xl shadow-2xl border-t-8 border-yellow-500 transform hover:scale-105 transition duration-500 delay-100">
                <p class="text-7xl mb-4 emoji-fix">🗓️</p>
                <h4 class="text-2xl font-bold text-yellow-600 mb-2">2. Book Items & Slot</h4>
                <p class="text-md text-gray-600">Select entitlements based on your monthly quota and choose a specific time slot to reserve stock.</p>
            </div>
            <div class="bg-white p-8 rounded-2xl shadow-2xl border-t-8 border-teal-500 transform hover:scale-105 transition duration-500 delay-200">
                <p class="text-7xl mb-4 emoji-fix">✅</p>
                <h4 class="text-2xl font-bold text-teal-600 mb-2">3. Collect with Token</h4>
                <p class="text-md text-gray-600">Present your unique **Collection Token** at the counter during your booked slot for efficient, no-queue collection.</p>
            </div>
        </div>
    </div>
    """
    
    # --- FEATURE: Quick Action Component for Admins/Public to use Admin features ---
    quick_action_html = f"""
    <div class="text-center mt-12 p-8 bg-blue-50 rounded-2xl shadow-inner border border-blue-200 max-w-7xl mx-auto px-6">
        <h3 class="text-3xl font-extrabold text-blue-900 mb-6">Quick Access to Key Portals</h3>
        <div class="flex justify-center gap-8 flex-wrap">
            <a href="{url_for('ration_rules_page')}" class="bg-blue-600 text-white px-8 py-4 rounded-xl font-bold hover:bg-blue-700 transition shadow-lg text-xl transform hover:scale-105">Download Ration Rules 📄</a>
            <a href="{url_for('admin_quota_check')}" class="bg-purple-600 text-white px-8 py-4 rounded-xl font-bold hover:bg-purple-700 transition shadow-lg text-xl transform hover:scale-105">Quota Check (Admin Utility) 🔍</a>
            <a href="{url_for('admin_token_validation')}" class="bg-red-600 text-white px-8 py-4 rounded-xl font-bold hover:bg-red-700 transition shadow-lg text-xl transform hover:scale-105">Token Validation (Admin Utility) 🔐</a>
        </div>
    </div>
    """

    content = f"""
    {stats_html}
    {process_html}
    {quick_action_html}
    """
    return render_template_string(get_layout("Welcome to Smart Ration", content, role))

@app.route("/how_it_works")
def how_it_works():
    content = f"""
    <div class="bg-white p-8 rounded-2xl shadow-2xl border-l-8 border-blue-600 max-w-3xl mx-auto">
        <h2 class="text-2xl font-bold mb-4 text-blue-900 flex items-center gap-2"><span class="emoji-fix">💡</span> Digital Collection Flow</h2>
        <ol class="list-decimal ml-6 space-y-3 text-lg text-gray-700">
            <li>**Registration & Verification:** New users register and await admin approval. Pre-registered users can skip this.</li>
            <li>**Policy Acceptance:** Once approved, users must accept the detailed **Ration Rules** to proceed to booking.</li>
            <li>**Item Selection:** Select required items. The system *automatically* calculates free quota utilization and cash payable for excess or non-free items.</li>
            <li>**Slot Booking & Token Generation:** Choose an available 15-minute slot. Upon selection, a unique 6-character **Collection Token** is generated, securing your stock.</li>
            <li>**Collection (Physical):** Visit the distribution center at the scheduled time. Present your Card and Token. The administrator verifies the token and stock is disbursed.</li>
            <li>**Payment:** Pay the calculated **Cash on Delivery (COD)** amount to the administrator. The order is then marked as collected/paid.</li>
        </ol>
    </div>
    """
    return render_template_string(get_layout("How It Works", content, 'guest'))

@app.route("/ration_rules", methods=['GET', 'POST'])
def ration_rules_page():
    db = get_db()
    
    if request.method == 'POST' and g.user:
        db.execute("UPDATE users SET policy_accepted=1 WHERE card_number=?", (g.user['card_number'],))
        db.commit()
        update_user_activity(g.user['card_number'], 'Accepted Ration Policy')
        flash("Ration Rules accepted. You can now proceed to book items.", "success")
        return redirect('/book_items')
        
    is_accepted = g.user and g.user['policy_accepted'] == 1

    policy_content = f"""
    <p class="font-bold text-xl mb-3 text-blue-900">Smart Ration System: Official Rules & Guidelines</p>
    <p class="mb-4 text-sm">**Purpose:** To ensure fair, transparent, and efficient distribution of subsidized and free ration items to eligible beneficiaries, preventing instances of fraud. **Last Updated:** {datetime.date.today().strftime('%d %B %Y')}</p>
    
    <p class="font-semibold mt-4 text-lg">1. Item Quotas and Pricing:</p>
    <ul class="list-disc list-inside ml-4 space-y-1">
        <li>**Rice:** A maximum of {get_config('max_free_rice_kg', 30)} kg per card is provided **FREE** of cost every month.</li>
        <li>**Wheat:** A maximum of {get_config('max_free_wheat_kg', 25)} kg per card is provided **FREE** of cost. Any quantity requested *above* this limit will be charged at a subsidized rate of **₹10.00 per kg**.</li>
        <li>**Other Items (Dal, Oil, Salt, Soap):** These are available at fixed subsidized prices. No free limits apply. Prices can be viewed on the booking page.</li>
    </ul>

    <p class="font-semibold mt-4 text-lg">2. Booking and Collection System:</p>
    <ul class="list-disc list-inside ml-4 space-y-1">
        <li>Items must be pre-booked online through this portal only to ensure stock availability.</li>
        <li>A specific **Collection Slot** must be booked after item selection to manage queues and prevent crowding.</li>
        <li>A unique **Token** is generated and must be presented at the store during the booked slot time. Tokens are valid *only* for the assigned slot.</li>
        <li>All payments for non-free items or excess quota are **Cash on Delivery (COD)** at the time of item collection.</li>
        <li>Missing a booked slot will lead to order cancellation and immediate release of reserved stock back into inventory. The user must place a new order.</li>
    </ul>
    
    <p class="font-semibold mt-4 text-lg">3. User Responsibilities:</p>
    <ul class="list-disc list-inside ml-4 space-y-1">
        <li>The card holder must present a valid ID proof and the Card/Token for collection.</li>
        <li>Any attempt to register with false information or abuse the quota system will result in **permanent card blockage** and potential legal action.</li>
        <li>Users must adhere to the maximum household size limit of {get_config('max_household_size', 10)} members for one card.</li>
    </ul>
    
    <p class="mt-6 text-sm font-bold text-red-600">By accepting these guidelines, you agree to abide by the terms. Misuse of the system may lead to permanent card blockage.</p>
    """
    
    form_html = ""
    if g.user and not is_accepted:
        form_html = f"""
        <form method="POST">
            <button class="bg-green-600 text-white px-6 py-3 rounded-xl font-bold text-xl hover:bg-green-700 mt-6 shadow-lg transform hover:scale-105 transition duration-300">
                <span class="emoji-fix">👍</span> I Understand and Accept Guidelines
            </button>
        </form>
        """
    elif g.user and is_accepted:
        form_html = """
        <div class="bg-green-100 border-l-4 border-green-500 text-green-700 p-4 rounded-xl mt-6 shadow-md">
            <p class="font-bold text-lg flex items-center gap-2"><span class="emoji-fix">✅</span> Status: Accepted</p>
            <p>Thank you. Your compliance allows you to access all beneficiary services. You are free to <a href="/book_items" class="font-bold underline text-green-800">Start Booking Items</a></p>
        </div>
        """
        
    content = f"""
    <div class="bg-white p-8 rounded-2xl shadow-2xl max-w-4xl mx-auto border-t-8 border-blue-600">
        <div class="policy-content border p-4 mb-4 h-96 overflow-y-scroll bg-gray-50 text-gray-700 rounded-lg">
            {policy_content}
        </div>
        {form_html}
    </div>
    """
    return render_template_string(get_layout("Ration Rules & Guidelines", content, 'user' if g.user else 'guest'))

@app.route("/register", methods=['GET', 'POST'])
def register():
    db = get_db()
    error = None
    message = None
    max_household_size = int(get_config('max_household_size', 10))
    
    # Regex for password validation (Max 8 chars, 1 upper, 1 lower, 1 number, 1 special)
    PASSWORD_PATTERN = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+])[A-Za-z\d!@#$%^&*()_+]{6,8}$")
    
    if request.method == 'POST':
        # Input Sanitization and Validation
        card_number = request.form['card_number'].strip()
        name = request.form['name'].strip()
        password = request.form['password'].strip()
        mobile = request.form.get('mobile', '').strip()
        address = request.form.get('address', '').strip()
        card_type = request.form.get('card_type', '').strip().upper()
        member_count = request.form.get('member_count', '1').strip()
        
        # 1. Card Number Validation (12 digits)
        if not re.match(r"^\d{12}$", card_number):
            error = "Invalid Card Number. Must be exactly **12 digits** (Numbers only)."
        
        # 2. Name validation
        if not error and not re.match(r"^[a-zA-Z\s]{2,}$", name):
            error = "Invalid name format. Only letters and spaces allowed."

        # 3. Member Count Validation
        try:
            member_count_val = int(member_count)
            if member_count_val < 1 or member_count_val > max_household_size:
                raise ValueError
        except ValueError:
            error = f"Member count must be between 1 and {max_household_size}."
            
        # 4. Password Validation (New complex rules, max 8 chars)
        if not error and not PASSWORD_PATTERN.match(password):
            error = "Invalid Password. Must be 6-8 characters, including at least one uppercase, one lowercase, one number, and one special symbol (!@#$%^&*()_+)."
            
        # 5. Mobile Validation
        if not error and mobile and not re.match(r"^\d{10}$", mobile):
            error = "Invalid mobile number. Must be 10 digits."


        if not error:
            try:
                password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
                db.execute("""
                    INSERT INTO users (card_number, name, password_hash, mobile_number, address, card_type,
                                       is_pre_registered, is_approved, policy_accepted, member_count, last_activity_date)
                    VALUES (?, ?, ?, ?, ?, ?, 0, 0, 0, ?, ?)
                """, (card_number, name, password_hash, mobile, address, card_type, member_count_val, datetime.datetime.now().isoformat()))
                db.commit()
                flash("Registration successful! Your account is pending admin approval.", "success")
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                error = "Card number already exists. Please check details or login."
            except Exception as e:
                error = f"An unexpected database error occurred: {e}"

    msg_html = f"<div class='bg-green-100 border-l-4 border-green-500 text-green-700 p-3 mb-4 rounded-lg'><p>{message}</p></div>" if message else ""
    err_html = f"<div class='bg-red-100 border-l-4 border-red-500 text-red-700 p-3 mb-4 rounded-lg'><p>{error}</p></div>" if error else ""
    
    # Client-side validation script
    password_check_script = """
    <script>
        function checkPasswordStrength(password) {
            const requirements = [
                { pattern: /.{6,8}/, message: "Length 6-8 characters" },
                { pattern: /[A-Z]/, message: "One Uppercase letter" },
                { pattern: /[a-z]/, message: "One Lowercase letter" },
                { pattern: /\d/, message: "One Number" },
                { pattern: /[!@#$%^&*()_+]/, message: "One Special Symbol (!@#$%^&*()_+)" }
            ];
            const feedbackElement = document.getElementById('password-feedback');
            let allPassed = true;
            let html = '';

            requirements.forEach(req => {
                const passed = req.pattern.test(password);
                const color = passed ? 'text-green-600' : 'text-red-600';
                const icon = passed ? '✅' : '❌';
                html += `<li class="${color}">${icon} ${req.message}</li>`;
                if (!passed) allPassed = false;
            });

            feedbackElement.innerHTML = `<ul class="list-none space-y-1">${html}</ul>`;
        }
    </script>
    """
    
    content = f"""
    <div class="bg-white p-8 rounded-2xl shadow-2xl max-w-xl mx-auto border-t-8 border-blue-600">
        <h2 class="text-3xl font-bold mb-6 text-blue-900 flex items-center gap-2"><span class="emoji-fix">📝</span> Beneficiary Registration</h2>
        {msg_html}{err_html}
        <form method="POST" class="grid grid-cols-1 gap-4">
            <input name="card_number" placeholder="Unique Card Number (12 digits only)" required class="border p-3 rounded-lg text-lg" pattern="\\d{{12}}" title="Card number must be exactly 12 digits" maxlength="12" value="{request.form.get('card_number', '')}">
            <input name="name" placeholder="Full Name (As per Card)" required class="border p-3 rounded-lg text-lg" value="{request.form.get('name', '')}">
            <input name="mobile" placeholder="Mobile Number (10 digits, Optional)" class="border p-3 rounded-lg text-lg" pattern="\\d{{10}}" maxlength="10" value="{request.form.get('mobile', '')}">
            <input name="card_type" placeholder="Card Type (e.g., APL, BPL)" class="border p-3 rounded-lg text-lg uppercase" value="{request.form.get('card_type', '')}">
            <input name="member_count" type="number" min="1" max="{max_household_size}" value="{request.form.get('member_count', '1')}" placeholder="Household Member Count (Max: {max_household_size})" class="border p-3 rounded-lg text-lg" required>
            <textarea name="address" placeholder="Full Address" class="border p-3 rounded-lg text-lg h-24">{request.form.get('address', '')}</textarea>
            
            <div class="relative">
                <input type="password" id="reg-password" name="password" placeholder="Set Password (6-8 chars, complex rules)" required class="border p-3 rounded-lg w-full text-lg pr-10" onkeyup="checkPasswordStrength(this.value)">
                <span class="absolute right-3 top-3 cursor-pointer emoji-fix" id="reg-password-toggle" onclick="togglePasswordVisibility('reg-password', 'reg-password-toggle')">👀</span>
            </div>
            
            <div id="password-feedback" class="bg-gray-50 p-3 rounded-lg border text-sm">
                <p class="font-bold text-gray-700 mb-1">Password Requirements:</p>
                <ul class="list-none space-y-1">
                    <li class="text-red-600">❌ Length 6-8 characters</li>
                    <li class="text-red-600">❌ One Uppercase letter</li>
                    <li class="text-red-600">❌ One Lowercase letter</li>
                    <li class="text-red-600">❌ One Number</li>
                    <li class="text-red-600">❌ One Special Symbol (!@#$%^&*()_+)</li>
                </ul>
            </div>
            
            <button class="mt-4 bg-green-600 text-white px-4 py-4 rounded-xl hover:bg-green-700 font-extrabold text-xl shadow-lg transform hover:scale-[1.02] transition duration-300">Submit Registration</button>
        </form>
        <p class="text-center text-sm text-gray-600 mt-4">Already registered? <a href="{url_for('login')}" class="text-blue-600 font-semibold hover:underline">Log In</a></p>
    </div>
    {password_check_script}
    """
    return render_template_string(get_layout("Register Beneficiary", content, 'guest'))

@app.route("/login", methods=['GET', 'POST'])
def login():
    db = get_db()
    error = None
    if request.method == 'POST':
        card_number = request.form['card_number'].strip()
        password = request.form['password'].strip()
        user = db.execute("SELECT * FROM users WHERE card_number = ?", (card_number,)).fetchone()
        
        if not user or user['is_admin'] == 1 or user['is_secondary_admin'] == 1:
            error = "Invalid credentials. Please check your Card Number."
        elif user['is_blocked'] == 1:
            error = "Your account is blocked by the administrator. Contact support."
        elif user['is_approved'] == 0 and user['is_pre_registered'] == 0:
            error = "Your online registration is pending admin approval."
        elif not bcrypt.check_password_hash(user['password_hash'], password):
            error = "Invalid credentials. Please check your password."
        else:
            session['user_id'] = user['card_number']
            update_user_activity(user['card_number'], 'Successful Login')
            # Initialize activity log after successful login
            session['activity_log'] = [{'type': 'Successful Login', 'time': datetime.datetime.now().isoformat()}]
            flash(f"Welcome back, {user['name']}!", "success")
            return redirect('/dashboard')

    err_html = f"<div class='bg-red-100 border-l-4 border-red-500 text-red-700 p-3 mb-4 rounded-lg'><p>{error}</p></div>" if error else ""
    content = f"""
    <div class="bg-white p-8 rounded-2xl shadow-2xl max-w-md mx-auto border-t-8 border-blue-600">
        <h2 class="text-3xl font-bold mb-6 text-blue-900 text-center">Beneficiary Login <span class="emoji-fix">🔑</span></h2>
        {err_html}
        <div class="bg-gray-100 p-3 mb-4 rounded-lg text-sm text-center font-semibold border-2 border-dashed border-red-300">
            TEST USER (Card: **123456789012**, Pass: **User@123**)
        </div>
        <form method="POST" class="space-y-4">
            <input name="card_number" placeholder="Card Number (12 digits)" required class="border p-3 rounded-lg w-full text-lg" pattern="\\d{{12}}" title="Card number must be exactly 12 digits" maxlength="12" value="{request.form.get('card_number', '')}">
            <div class="relative">
                <input type="password" id="login-password" name="password" placeholder="Password (6-8 chars, complex rules)" required class="border p-3 rounded-lg w-full text-lg pr-10">
                <span class="absolute right-3 top-3 cursor-pointer emoji-fix" id="login-password-toggle" onclick="togglePasswordVisibility('login-password', 'login-password-toggle')">👀</span>
            </div>
            <button class="bg-blue-600 text-white px-4 py-4 rounded-xl w-full font-extrabold text-xl hover:bg-blue-700 shadow-lg transform hover:scale-[1.01] transition duration-300">Secure Login</button>
        </form>
        <p class="text-sm text-gray-600 mt-6 text-center">New Card? <a href="{url_for('register')}" class="text-green-600 font-semibold hover:underline">Register Here</a></p>
        <p class="text-sm text-gray-600 mt-2 text-center">Administration: <a href="{url_for('admin_login')}" class="text-yellow-700 font-semibold hover:underline">Admin Login</a></p>
    </div>
    """
    return render_template_string(get_layout("Login", content, 'guest'))

@app.route("/logout")
def logout():
    # Update user activity only if they were actually logged in (g.user is set)
    if g.user:
        update_user_activity(g.user['card_number'], 'Logged Out')
    session.clear()
    flash("You have been securely logged out.", "info")
    return redirect('/')

# ============================================================
# USER ROUTES
# ============================================================

@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    user = g.user
    
    order_counts = db.execute("""
        SELECT
            SUM(CASE WHEN is_paid = 1 THEN 1 ELSE 0 END) AS collected_count,
            SUM(CASE WHEN is_paid = 0 THEN 1 ELSE 0 END) AS pending_count
        FROM (SELECT DISTINCT token, is_paid FROM orders WHERE card_number=?)
    """, (user['card_number'],)).fetchone()
    
    collected_count = order_counts['collected_count'] or 0
    pending_count = order_counts['pending_count'] or 0
    total_orders = collected_count + pending_count
    
    max_rice = float(get_config('max_free_rice_kg', 30))
    max_wheat = float(get_config('max_free_wheat_kg', 25))
    
    rice_progress = int((user['monthly_collected_kg_rice'] / max_rice) * 100) if max_rice > 0 else 0
    wheat_progress = int((user['monthly_collected_kg_wheat'] / max_wheat) * 100) if max_wheat > 0 else 0
    
    # Card Display HTML (Enhanced)
    card_html = f"""
    <div class="card-gradient p-6 rounded-2xl shadow-2xl w-full border-b-8 border-yellow-400 transform hover:scale-105 transition duration-300 text-white">
        <h3 class="text-2xl font-extrabold mb-4 text-yellow-400 border-b border-gray-600 pb-2">Your Smart Ration Card</h3>
        <div class="flex justify-between items-start">
            <div>
                <p class="text-sm text-gray-400">Card Holder:</p>
                <p class="text-2xl font-bold mb-2">{user['name']}</p>
                <p class="text-sm text-gray-400">Card Number:</p>
                <p class="text-xl font-mono mb-2">{user['card_number']}</p>
                <p class="text-sm text-gray-400">Type / Members:</p>
                <p class="text-lg font-bold text-red-300">{user['card_type'] or 'N/A'} | {user['member_count']} Persons</p>
            </div>
            {f"<img src='{url_for('uploads', filename=user['photo_filename'])}' class='h-24 w-24 rounded-full object-cover border-4 border-white shadow-lg' alt='User Photo'>" if user['photo_filename'] else f"<div class='h-24 w-24 rounded-full bg-blue-600 flex items-center justify-center text-4xl font-bold text-white border-4 border-white'> {get_user_initials(user['name'])} </div>"}
        </div>
        <p class="mt-4 text-xs text-right text-gray-500">Status: {'Approved' if user['is_approved']==1 else 'Pending'} | Policy: {'Accepted' if user['policy_accepted']==1 else 'Required'}</p>
    </div>
    """
    
    # Quota Card HTML (Enhanced)
    quota_card_html = f"""
    <div class="bg-white p-6 rounded-2xl shadow-2xl border-l-8 border-green-600">
        <h3 class="text-2xl font-extrabold text-green-800 mb-4 flex items-center gap-2"><span class="emoji-fix">🍚</span> Monthly Quota Tracker</h3>
        
        <div class="mb-4">
            <p class="text-lg font-semibold text-gray-800">Rice Collected: {user['monthly_collected_kg_rice']:.1f} kg / {max_rice:.1f} kg Free</p>
            <div class="w-full bg-gray-200 rounded-full h-2.5">
                <div class="bg-green-600 h-2.5 rounded-full" style="width: {rice_progress}%;"></div>
            </div>
            <p class="text-xs text-right text-gray-500 mt-1">Free Rice Remaining: **{max(0.0, max_rice - user['monthly_collected_kg_rice']):.1f} kg**</p>
        </div>
        
        <div class="mb-4">
            <p class="text-lg font-semibold text-gray-800">Wheat Collected: {user['monthly_collected_kg_wheat']:.1f} kg / {max_wheat:.1f} kg Free</p>
            <div class="w-full bg-gray-200 rounded-full h-2.5">
                <div class="bg-green-600 h-2.5 rounded-full" style="width: {wheat_progress}%;"></div>
            </div>
            <p class="text-xs text-right text-gray-500 mt-1">Free Wheat Remaining: **{max(0.0, max_wheat - user['monthly_collected_kg_wheat']):.1f} kg**</p>
        </div>
        
        <p class="text-sm font-medium text-blue-700 mt-4">Quota resets automatically on the 1st of every month.</p>
    </div>
    """
    
    # Order Status Card (Enhanced)
    order_status_card_html = f"""
    <div class="bg-white p-6 rounded-2xl shadow-2xl border-l-8 border-yellow-600">
        <h3 class="text-2xl font-extrabold text-yellow-800 mb-4 flex items-center gap-2"><span class="emoji-fix">🛒</span> Order Status</h3>
        <p class="text-lg">Total Tokens Placed: <span class="font-extrabold text-blue-600">{total_orders}</span></p>
        <p class="text-lg">Pending Collection: <span class="font-extrabold text-red-600">{pending_count}</span></p>
        <p class="text-lg">Collected/Paid: <span class="font-extrabold text-green-600">{collected_count}</span></p>
        <div class="mt-4 flex flex-col gap-3">
            <a href="{url_for('book_items')}" class="bg-blue-600 text-white px-6 py-3 rounded-xl font-bold text-lg hover:bg-blue-700 shadow-lg text-center transform hover:scale-[1.01]">🛒 New Item Booking</a>
            <a href="{url_for('history')}" class="bg-gray-600 text-white px-6 py-3 rounded-xl font-bold text-lg hover:bg-gray-700 shadow-lg text-center transform hover:scale-[1.01]">📋 View History</a>
        </div>
    </div>
    """
    
    # --- FEATURE: User Activity Log Card ---
    activities = session.get('activity_log', [])
    activity_html = """
    <div class="bg-white p-6 rounded-2xl shadow-2xl border-l-8 border-purple-600 lg:col-span-3">
        <h3 class="text-2xl font-extrabold text-purple-800 mb-4 flex items-center gap-2"><span class="emoji-fix">⏱️</span> Recent Activity Log</h3>
        <ul class="space-y-2">
            """
    if activities:
        for activity in activities:
            type_text = activity['type']
            time_text = format_datetime_since(activity['time'])
            activity_html += f"""
            <li class="flex justify-between text-sm border-b pb-1">
                <span class="font-medium text-gray-700">{type_text}</span>
                <span class="text-gray-500">{time_text}</span>
            </li>
            """
    else:
        activity_html += "<li class='text-gray-500'>No recent activity recorded.</li>"
        
    activity_html += "</ul></div>"
    # --- END FEATURE ---

    content = f"""
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-8">
        <div class="lg:col-span-1">
            {card_html}
        </div>
        <div class="lg:col-span-2 grid grid-cols-1 md:grid-cols-2 gap-6">
            {quota_card_html}
            {order_status_card_html}
        </div>
        {activity_html}
    </div>
    """
    return render_template_string(get_layout("Beneficiary Dashboard", content, 'user'))

@app.route("/profile", methods=['GET', 'POST'])
@login_required
def profile():
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE card_number = ?', (g.user['card_number'],)).fetchone()
    error = None
    
    max_household_size = int(get_config('max_household_size', 10))

    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'delete_photo':
            if user['photo_filename']:
                try:
                    os.remove(os.path.join(UPLOAD_DIR, user['photo_filename']))
                    db.execute("UPDATE users SET photo_filename=? WHERE card_number=?", (None, user['card_number']))
                    db.commit()
                    update_user_activity(g.user['card_number'], 'Profile Photo Deleted')
                    flash("Profile photo removed successfully.", "success")
                except Exception as e:
                    error = f"Error deleting photo: {e}"
            else:
                error = "No photo is currently set."
        
        elif action == 'update_profile':
            name = request.form.get('name', user['name']).strip()
            mobile = request.form.get('mobile_number', user['mobile_number'] or "").strip()
            address = request.form.get('address', user['address'] or "").strip()
            card_type = request.form.get('card_type', user['card_type'] or "").strip().upper()
            member_count = request.form.get('member_count', str(user['member_count'])).strip()
            uploaded = request.files.get('photo')
            photo_filename = user['photo_filename']

            try:
                member_count_val = int(member_count)
                if member_count_val < 1 or member_count_val > max_household_size:
                    raise ValueError(f"Member count must be between 1 and {max_household_size}.")
            except ValueError as e:
                error = str(e) or "Member count must be a positive whole number."
                
            if not error and mobile and not re.match(r"^\d{10}$", mobile):
                error = "Invalid mobile number. Must be 10 digits."


            if not error and uploaded and uploaded.filename:
                ext = os.path.splitext(uploaded.filename)[1].lower()
                if ext not in ['.jpg', '.jpeg', '.png']:
                    error = "Photo must be JPG or PNG."
                else:
                    try:
                        unique_name = f"{user['card_number']}_{uuid.uuid4().hex}{ext}"
                        save_path = os.path.join(UPLOAD_DIR, unique_name)
                        uploaded.save(save_path)
                        
                        # Delete old photo if it exists
                        if user['photo_filename'] and os.path.exists(os.path.join(UPLOAD_DIR, user['photo_filename'])):
                            os.remove(os.path.join(UPLOAD_DIR, user['photo_filename']))
                            
                        photo_filename = unique_name
                    except Exception as e:
                        error = f"Error saving photo: {e}"

            if not error:
                try:
                    db.execute("""
                        UPDATE users SET name=?, mobile_number=?, address=?, card_type=?, member_count=?, photo_filename=?
                        WHERE card_number=?
                    """, (name, mobile, address, card_type, int(member_count), photo_filename, user['card_number']))
                    db.commit()
                    update_user_activity(g.user['card_number'], 'Profile Details Updated')
                    flash("Profile updated successfully.", "success")
                except sqlite3.Error:
                    error = "Database Error updating profile."
        
        if error:
            flash(error, "error")
        
        # Re-fetch user data after POST action
        user = db.execute('SELECT * FROM users WHERE card_number = ?', (g.user['card_number'],)).fetchone()
        return redirect(url_for('profile'))

    user = db.execute('SELECT * FROM users WHERE card_number = ?', (g.user['card_number'],)).fetchone()
    
    # Large photo display uses different sizing/border than dashboard badge
    photo_display = f"""
        <img src="{url_for('uploads', filename=user['photo_filename'])}" class="h-28 w-28 rounded-full object-cover border-4 border-blue-600 shadow-lg" alt="User Photo">
    """ if user['photo_filename'] else f"""
        <div class="h-28 w-28 rounded-full bg-blue-600 flex items-center justify-center text-5xl font-bold text-white border-4 border-blue-600 shadow-lg">{get_user_initials(user['name'])}</div>
    """
    
    # --- FEATURE: Photo Delete Button ---
    delete_photo_btn = ""
    if user['photo_filename']:
        delete_photo_btn = f"""
        <form method="POST" class="mt-2" onsubmit="return confirm('Are you sure you want to delete your profile photo?');">
            <input type="hidden" name="action" value="delete_photo">
            <button type="submit" class="text-red-500 hover:text-red-700 text-sm font-semibold flex items-center gap-1">
                <span class="emoji-fix">🗑️</span> Delete Current Photo
            </button>
        </form>
        """

    err_html = f'<div class="bg-red-100 border-l-4 border-red-500 text-red-700 p-3 mb-4 rounded-lg"><p>{error}</p></div>' if error else ""
    content = f"""
    <div class="bg-white p-8 rounded-2xl shadow-2xl max-w-3xl mx-auto border-t-8 border-blue-600">
        <h2 class="text-3xl font-bold mb-6 text-blue-900 flex items-center gap-2"><span class="emoji-fix">🧑‍💻</span> Your Beneficiary Profile</h2>
        {err_html}
        <div class="flex items-start gap-6 mb-6 pb-4 border-b border-gray-200">
            <div>
                {photo_display}
                {delete_photo_btn}
            </div>
            <div>
                <p class="text-2xl font-extrabold">{user['name']}</p>
                <p class="text-md text-gray-600">Card: **{user['card_number']}**</p>
                <p class="text-md text-gray-600">Status: <span class="font-bold text-{'green' if user['is_approved']==1 else 'red'}-600">{'Approved' if user['is_approved']==1 else 'Pending'}</span></p>
                <p class="text-xs text-gray-400 mt-2">Last Activity: {format_datetime_since(user['last_activity_date'])}</p>
            </div>
        </div>
        <form method="POST" enctype="multipart/form-data" class="grid grid-cols-1 gap-4">
            <input type="hidden" name="action" value="update_profile">
            <input name="name" value="{user['name']}" class="border p-3 rounded-lg text-lg" placeholder="Full Name">
            <input name="card_type" value="{user['card_type'] or ''}" class="border p-3 rounded-lg text-lg uppercase" placeholder="Card Type (e.g., APL, BPL)">
            <input name="mobile_number" value="{user['mobile_number'] or ''}" class="border p-3 rounded-lg text-lg" placeholder="Mobile" pattern="\\d{{10}}" maxlength="10">
            <input name="member_count" type="number" min="1" max="{max_household_size}" value="{user['member_count']}" class="border p-3 rounded-lg text-lg" placeholder="Household Member Count">
            <textarea name="address" class="w-full px-3 py-2 border rounded-lg text-lg h-24" placeholder="Address">{user['address'] or ''}</textarea>
            <label class="text-sm text-gray-600 mt-2 font-semibold">Update Photo (JPG/PNG - Recommended)</label>
            <input type="file" name="photo" accept=".jpg,.jpeg,.png" class="border p-3 rounded-lg bg-gray-50">
            <button class="bg-blue-600 text-white px-4 py-4 rounded-xl font-extrabold text-xl hover:bg-blue-700 mt-4 shadow-lg transform hover:scale-[1.01]">Update Profile Details</button>
        </form>
    </div>
    """
    return render_template_string(get_layout("Profile Details", content, 'user'))

@app.route("/history")
@login_required
def history():
    db = get_db()
    # Query structure confirmed to group by token and show total cost/min paid status
    orders = db.execute("""
        SELECT token, MIN(order_date) as date, SUM(total_cost) as total_cost, MIN(is_paid) as is_paid
        FROM orders WHERE card_number = ?
        GROUP BY token ORDER BY date DESC
    """, (g.user['card_number'],)).fetchall()

    list_html = ""
    for o in orders:
        try:
            dt = datetime.datetime.fromisoformat(o['date'])
            pretty = dt.strftime('%d %b %Y, %I:%M %p')
        except ValueError:
            pretty = "Unknown Date"
            
        status = "Collected & Paid" if o['is_paid'] == 1 else "Pending Collection"
        status_color = "text-green-600" if o['is_paid'] == 1 else "text-red-600"
        
        list_html += f"""
        <div class="bg-white p-5 rounded-xl shadow-lg mb-4 border-l-8 border-{'green' if o['is_paid']==1 else 'red'}-600 hover:shadow-xl transition duration-300">
            <div class="flex justify-between items-center">
                <div>
                    <p class="font-extrabold text-xl text-blue-800">Token: <span class="text-red-700">{o['token']}</span></p>
                    <p class="text-sm text-gray-600 mt-1">Date Placed: {pretty}</p>
                </div>
                <div class="text-right">
                    <p class="text-2xl font-extrabold text-gray-800">₹{o['total_cost']:.2f}</p>
                    <p class="text-md {status_color} font-bold">{status}</p>
                    <a href="{url_for('history_detail', token=o['token'])}" class="text-blue-600 text-sm font-semibold hover:underline">View Details &rarr;</a>
                </div>
            </div>
        </div>
        """

    content = f"""
    <div class="max-w-3xl mx-auto">
        <h2 class="text-3xl font-bold mb-6 text-blue-900 flex items-center gap-2"><span class="emoji-fix">📜</span> Your Order History</h2>
        <p class="text-gray-600 mb-6 text-lg">This lists all your booking tokens and their collection status.</p>
        {list_html if list_html else "<p class='text-xl font-bold text-gray-600 p-6 bg-gray-100 rounded-xl border border-gray-300'>No past orders found. Place your first order today!</p>"}
    </div>
    """
    return render_template_string(get_layout("Order History", content, 'user'))

@app.route("/history/<token>")
@login_required
def history_detail(token):
    db = get_db()
    token = token.strip().upper()
    if not re.match(r"^[A-Z0-9]{6}$", token):
        flash("Invalid token format.", "error")
        return redirect('/history')
        
    orders = db.execute("""
        SELECT o.*, s.date_time, i.unit, i.unit_price
        FROM orders o
        JOIN slots s ON o.slot_id = s.id
        JOIN items i ON o.item_name = i.name
        WHERE o.token = ? AND o.card_number = ?
    """, (token, g.user['card_number'])).fetchall()

    if not orders:
        flash("Order not found or access denied.", "error")
        return redirect('/history')

    first_order = orders[0]
    total_calculated_cost = sum(item['total_cost'] for item in orders)
    slot_time = datetime.datetime.strptime(first_order['date_time'], '%Y-%m-%d %H:%M:%S').strftime('%A, %d %b %Y at %I:%M %p')
    
    items_html = ""
    for o in orders:
        free_info = f"<span class='text-green-700 font-semibold'>({o['free_qty']:.1f} {o['unit']} FREE)</span>" if o['free_qty'] > 0 else ""
        price_info = f"@ ₹{o['unit_price']:.2f}/{o['unit']}" if o['total_cost'] > 0 else "Free of Cost"
        items_html += f"""
        <li class="flex justify-between border-b py-3 hover:bg-gray-50 px-2 rounded">
            <div>
                <span class="font-bold text-gray-800 text-lg">{o['item_name']}</span>
                <span class="text-gray-600 text-md">({o['quantity']:.1f} {o['unit']}) {free_info}</span>
            </div>
            <div class="text-right">
                <span class="font-bold text-red-600 text-xl">₹{o['total_cost']:.2f}</span>
                <p class="text-xs text-gray-500">{price_info}</p>
            </div>
        </li>
        """

    content = f"""
    <div class="max-w-3xl mx-auto bg-white p-8 rounded-2xl shadow-2xl border-t-8 border-blue-600">
        <h2 class="text-3xl font-bold mb-4 text-blue-900">Collection Token: <span class="text-red-700">{token}</span></h2>
        
        <div class="bg-gray-100 p-4 rounded-xl mb-6 border border-gray-300">
            <p class="text-md text-gray-600 mb-2">Scheduled Collection Slot:</p>
            <p class="text-2xl font-extrabold text-red-700">{slot_time}</p>
        </div>
        
        <p class="text-md text-gray-600 mb-6">Status: <span class="font-extrabold text-{'green' if first_order['is_paid']==1 else 'red'}-600 text-lg">{'Collected & Paid' if first_order['is_paid']==1 else 'Pending Collection'}</span></p>

        <h3 class="text-2xl font-extrabold mt-4 mb-3 border-b-2 pb-2 text-gray-800">Items Summary</h3>
        <ul class="space-y-1 divide-y divide-gray-200">
            {items_html}
        </ul>
        
        <div class="mt-6 pt-4 border-t-4 border-dashed border-gray-400 bg-blue-50 p-4 rounded-xl">
            <div class="flex justify-between items-center text-3xl font-extrabold">
                <span>TOTAL DUE (COD)</span>
                <span class="text-green-700">₹{total_calculated_cost:.2f}</span>
            </div>
        </div>
        <p class="text-center mt-6"><a href="{url_for('history')}" class="text-blue-600 font-semibold hover:underline flex items-center justify-center gap-1"><span class="emoji-fix">⬅️</span> Back to History</a></p>
    </div>
    """
    return render_template_string(get_layout(f"Token Details: {token}", content, 'user'))

@app.route("/book_items", methods=['GET', 'POST'])
@login_required
def book_items():
    db = get_db()
    user = g.user

    if str(get_config('system_freeze', '0')) == '1':
        flash("System is currently frozen. No new bookings allowed. Please try again later.", "warning")
        return redirect('/dashboard')

    if user['is_blocked'] == 1:
        flash("Your account is blocked. Please contact admin.", "error")
        return redirect('/dashboard')

    if user['policy_accepted'] == 0:
        flash("You must accept the distribution policy before booking items.", "warning")
        return redirect('/ration_rules')

    if request.method == 'POST':
        item_quantities = {}
        total_cost = 0.0
        order_details = []
        items_db = db.execute("SELECT * FROM items").fetchall()
        
        max_rice = float(get_config('max_free_rice_kg', 30))
        max_wheat = float(get_config('max_free_wheat_kg', 25))
        
        # Current status
        current_rice_collected = user['monthly_collected_kg_rice']
        current_wheat_collected = user['monthly_collected_kg_wheat']
        
        free_rice_available = max(0.0, max_rice - current_rice_collected)
        free_wheat_available = max(0.0, max_wheat - current_wheat_collected)

        error = None
        warning = None
        
        total_rice_requested = 0.0
        total_wheat_requested = 0.0
        
        # Temporary copies for quota calculation during the loop
        temp_free_rice_available = free_rice_available
        temp_free_wheat_available = free_wheat_available

        for item in items_db:
            quantity_str = request.form.get(f"item_{item['id']}")
            if quantity_str:
                try:
                    qty = float(quantity_str)
                    if qty < 0.0:
                        raise ValueError("Quantity must be non-negative.")
                    if qty == 0.0:
                        continue
                    item_quantities[item['name']] = qty
                    
                    if item['name'] == 'Rice':
                        total_rice_requested += qty
                    elif item['name'] == 'Wheat':
                        total_wheat_requested += qty
                        
                except ValueError:
                    error = "Invalid quantity provided. Please use numbers."
                    break
        
        # --- QUOTA CHECKS & COST CALCULATION ---
        if not error:
            if total_rice_requested > max_rice:
                warning = f"You requested {total_rice_requested:.1f} kg of Rice. This exceeds your maximum free quota of {max_rice:.1f} kg. The excess will be free this month, but future policy changes may result in costs."
            if total_wheat_requested > max_wheat:
                excess_wheat = max(0.0, total_wheat_requested - max_wheat)
                excess_cost = excess_wheat * 10.0  
                if excess_cost > 0.0:
                    warning_msg = f"You requested {total_wheat_requested:.1f} kg of Wheat. This exceeds your free quota of {max_wheat:.1f} kg. The excess {excess_wheat:.1f} kg will cost approximately ₹{excess_cost:.2f}."
                    warning = warning_msg if not warning else f"{warning} | {warning_msg}"
        # --- END QUOTA CHECKS ---


        if not item_quantities and not error:
            error = "Please select at least one item."

        if not error:
            try:
                db.execute('BEGIN TRANSACTION')
                
                for name, quantity in item_quantities.items():
                    item = next(i for i in items_db if i['name'] == name)
                    
                    # --- ATOMIC STOCK RESERVATION ---
                    cursor = db.execute("UPDATE items SET stock = stock - ? WHERE name = ? AND stock >= ?", (quantity, name, quantity))
                    
                    if cursor.rowcount == 0:
                        current_stock_row = db.execute("SELECT stock FROM items WHERE name = ?", (name,)).fetchone()
                        current_stock = current_stock_row['stock']
                        error = f"Requested quantity ({quantity:.1f} {item['unit']}) for {name} exceeds current stock ({current_stock:.1f} {item['unit']})."
                        break
                    # --- END ATOMIC CHECK ---

                    free_qty = 0.0
                    
                    if name == 'Rice':
                        # Rice is free (price 0.0), but we track usage against the limit for reporting
                        free_qty = quantity 
                    elif name == 'Wheat':
                        # Wheat is partially free
                        free_qty = min(quantity, temp_free_wheat_available)
                        temp_free_wheat_available -= free_qty
                        
                    paid_qty = quantity - free_qty
                    cost = paid_qty * item['unit_price']
                    total_cost += cost

                    order_details.append({
                        'item_name': name,
                        'quantity': quantity,
                        'unit': item['unit'],
                        'cost': cost,
                        'free_qty': free_qty, # This is the amount that consumes the monthly quota
                        'paid_qty': paid_qty,
                        'unit_price': item['unit_price']
                    })

                if error:
                    db.rollback()
                    flash(error, "error")
                    return redirect(url_for("book_items"))

                session['temp_order'] = {'items': order_details, 'total_cost': total_cost}
                db.commit()
                
                if warning:
                     flash(warning, "warning")
                    
                flash(f"Items reserved. Total calculated cost: ₹{total_cost:.2f}. Now choose your slot to finalize.", "info")
                return redirect(url_for("book_slot"))

            except Exception as e:
                db.rollback()
                flash(f"An unexpected error occurred during item selection: {e}", "error")
                return redirect(url_for("book_items"))

    items = db.execute("SELECT * FROM items ORDER BY name").fetchall()
    max_rice = float(get_config('max_free_rice_kg', 30))
    max_wheat = float(get_config('max_free_wheat_kg', 25))
    free_rice_available = max_rice - user['monthly_collected_kg_rice']
    free_wheat_available = max_wheat - user['monthly_collected_kg_wheat']
    if free_rice_available < 0: free_rice_available = 0.0
    if free_wheat_available < 0: free_wheat_available = 0.0
    
    # Pass item data to JS for dynamic calculation
    items_json = json.dumps([
        {'id': i['id'], 'name': i['name'], 'price': i['unit_price'], 'unit': i['unit'], 'stock': i['stock'], 'free_limit': i['free_limit_kg']} 
        for i in items
    ])
    
    quota_json = json.dumps({
        'max_rice': max_rice,
        'max_wheat': max_wheat,
        'free_rice_available': free_rice_available,
        'free_wheat_available': free_wheat_available
    })

    items_html = ""
    for item in items:
        info_class = "text-blue-600"
        
        if item['name'] == 'Rice':
            limit = f"Free Quota Left: {free_rice_available:.1f}/{max_rice:.1f} {item['unit']} @ ₹0.0/kg"
            if free_rice_available <= 0: info_class = "text-red-600"
        elif item['name'] == 'Wheat':
            limit = f"Free Quota Left: {free_wheat_available:.1f}/{max_wheat:.1f} {item['unit']} @ ₹0.0/kg. Excess @ ₹{item['unit_price']:.2f}/kg"
            if free_wheat_available <= 0: info_class = "text-red-600"
        else:
            limit = f"Subsidized Price: ₹{item['unit_price']:.2f}/{item['unit']}. No free limit applies."
            info_class = "text-green-600"

        items_html += f"""
        <div class="flex justify-between items-center border-b pb-4 pt-4 hover:bg-gray-50 p-2 rounded-lg transition duration-150">
            <div class="flex-grow mr-4">
                <p class="font-extrabold text-gray-800 text-xl flex items-center gap-2">
                    <span class="emoji-fix">📦</span> {item['name']}
                    <span class="text-sm text-gray-500 font-normal">({item['stock']:.1f} {item['unit']} in stock)</span>
                </p>
                <p class="text-xs {info_class} mt-1 font-medium">{limit}</p>
            </div>
            <div class="w-36 flex items-center gap-2">
                <input type="number" step="0.1" min="0" max="{item['stock']}" name="item_{item['id']}" id="item_qty_{item['id']}" oninput="updatePricePreview()" value="{request.form.get(f'item_{item['id']}', '')}" placeholder="0.0" class="border p-2 rounded-lg text-center w-full text-lg font-semibold">
                <span class="text-gray-600 font-semibold">{item['unit']}</span>
            </div>
        </div>
        """
        
    # --- FEATURE: Dynamic Price Preview Box (for Book Items page) ---
    price_preview_html = f"""
    <div class="bg-yellow-50 p-4 rounded-xl mb-6 border border-yellow-300 shadow-inner">
        <p class="font-bold text-yellow-800 text-lg flex items-center gap-2"><span class="emoji-fix">💰</span> Estimated Cost (Before Slot Booking)</p>
        <div class="flex justify-between mt-2">
            <span class="text-md text-gray-700 font-medium">Estimated COD:</span>
            <span id="estimated-cost" class="text-3xl font-extrabold text-red-600">₹0.00</span>
        </div>
        <p id="cost-breakdown" class="text-sm text-gray-600 mt-2 border-t pt-1"></p>
    </div>
    """
    
    calculation_script = f"""
    <script>
        const itemData = {items_json};
        const quotaData = {quota_json};

        function updatePricePreview() {{
            let totalCost = 0.0;
            let totalRiceFree = 0.0;
            let totalWheatFree = 0.0;
            let tempRiceFreeAvailable = quotaData.free_rice_available;
            let tempWheatFreeAvailable = quotaData.free_wheat_available;
            let breakdownHtml = '';

            itemData.forEach(item => {{
                const input = document.getElementById(`item_qty_${{item.id}}`);
                const qty = parseFloat(input.value) || 0;
                
                if (qty > 0) {{
                    let cost = 0.0;
                    let freeQty = 0.0;
                    let paidQty = 0.0;
                    
                    if (item.name === 'Rice') {{
                        freeQty = qty; // All rice is free (price 0.0)
                        totalRiceFree += qty;
                    }} else if (item.name === 'Wheat') {{
                        freeQty = Math.min(qty, tempWheatFreeAvailable);
                        paidQty = qty - freeQty;
                        cost = paidQty * item.price;
                        tempWheatFreeAvailable -= freeQty;
                        totalWheatFree += freeQty;
                    }} else {{
                        // Other subsidized items
                        paidQty = qty;
                        cost = paidQty * item.price;
                    }}
                    
                    totalCost += cost;
                    
                    breakdownHtml += `
                        <div class="flex justify-between text-sm">
                            <span class="text-gray-600">${{item.name}} (${{qty.toFixed(1)}} ${{item.unit}})</span>
                            <span class="font-semibold text-gray-800">
                                <span class="text-green-600">${{freeQty.toFixed(1)}} Free</span> | 
                                <span class="text-red-600">₹${{cost.toFixed(2)}} Due</span>
                            </span>
                        </div>
                    `;
                }}
            }});

            document.getElementById('estimated-cost').innerText = `₹${{totalCost.toFixed(2)}}`;
            document.getElementById('cost-breakdown').innerHTML = breakdownHtml || 'Enter quantities above to see the cost breakdown.';
        }}

        // Initial call to set up the view
        document.addEventListener('DOMContentLoaded', updatePricePreview);
    </script>
    """
    # --- END FEATURE: Dynamic Price Preview Box ---

    content = f"""
    <div class="bg-white p-8 rounded-2xl shadow-2xl max-w-3xl mx-auto border-t-8 border-green-600">
        <h2 class="text-3xl font-bold mb-6 text-green-800 flex items-center gap-2"><span class="emoji-fix">1️⃣</span> Step 1: Select Items & Quantities</h2>
        <p class="text-md text-gray-600 mb-6 font-medium">Enter the quantity you require in kilograms (kg), Litres (Litre), or pieces (pc). Your available free quotas are displayed below:</p>
        
        <div class="bg-blue-50 p-4 rounded-xl mb-6 border border-blue-200 shadow-inner">
            <p class="font-bold text-blue-800 text-lg">My Quota Status:</p>
            <p class="text-md">Rice Free Left: **{free_rice_available:.1f} kg** / Wheat Free Left: **{free_wheat_available:.1f} kg**</p>
        </div>
        
        {price_preview_html}
        
        <form method="POST">
            {items_html}
            <button class="w-full bg-blue-600 text-white px-4 py-4 rounded-xl mt-8 font-extrabold text-xl hover:bg-blue-700 shadow-lg transform hover:scale-[1.01]">
                <span class="emoji-fix">➡️</span> Step 2: Choose Collection Slot
            </button>
        </form>
    </div>
    {calculation_script}
    """
    return render_template_string(get_layout("Book Items", content, 'user'))

@app.route("/book_slot", methods=['GET', 'POST'])
@login_required
def book_slot():
    db = get_db()
    temp_order = session.get('temp_order')

    if not temp_order:
        flash("No items selected. Start a new order.", "warning")
        return redirect(url_for("book_items"))
        
    if str(get_config('system_freeze', '0')) == '1':
        db.execute('BEGIN TRANSACTION')
        for item in temp_order['items']:
            db.execute("UPDATE items SET stock = stock + ? WHERE name = ?", (item['quantity'], item['item_name']))
        db.commit()
        
        session.pop('temp_order', None)
        flash("System is currently frozen. Stock reservation released.", "warning")
        return redirect('/dashboard')

    if request.method == 'POST':
        slot_id = request.form.get("slot_id")
        error = None

        if not slot_id:
            error = "Please select a collection slot."
        
        if not error:
            try:
                # Use IMMEDIATE TRANSACTION for strong locking during finalization
                db.execute('BEGIN IMMEDIATE TRANSACTION')
                
                slot = db.execute("SELECT * FROM slots WHERE id = ? AND booked_count < capacity", (slot_id,)).fetchone()
                if not slot:
                    error = "Selected slot is full or invalid. Please choose another."
                
                if not error:
                    token = uuid.uuid4().hex[:6].upper()
                    order_date = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                    # 1. Insert order details
                    for item in temp_order['items']:
                        db.execute("""
                            INSERT INTO orders (card_number, slot_id, item_name, quantity, total_cost, order_date, token, free_qty, paid_qty)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, (g.user['card_number'], slot_id, item['item_name'], item['quantity'], item['cost'], order_date, token, item['free_qty'], item['paid_qty']))

                    # 2. Update slot capacity
                    db.execute("UPDATE slots SET booked_count = booked_count + 1 WHERE id = ?", (slot_id,))

                    # 3. Update user collected quotas
                    rice_collected = sum(i['free_qty'] for i in temp_order['items'] if i['item_name'] == 'Rice')
                    wheat_collected = sum(i['free_qty'] for i in temp_order['items'] if i['item_name'] == 'Wheat')

                    if rice_collected > 0 or wheat_collected > 0:
                        db.execute("""
                            UPDATE users SET
                            monthly_collected_kg_rice = monthly_collected_kg_rice + ?,
                            monthly_collected_kg_wheat = monthly_collected_kg_wheat + ?
                            WHERE card_number = ?
                        """, (rice_collected, wheat_collected, g.user['card_number']))

                    db.commit() # FINAL COMMIT
                    session.pop('temp_order')
                    update_user_activity(g.user['card_number'], f'Placed New Order ({token})')
                    # CRITICAL FIX: Ensure the SUCCESS flash is clearly visible
                    flash(f"Order confirmed! Your collection token is: **{token}**. Please be ready to pay ₹{temp_order['total_cost']:.2f} at collection.", "success")
                    # FIX: Redirect to dashboard after successful order completion
                    return redirect(url_for("dashboard"))
                else:
                    raise Exception(error) # Trigger rollback path below

            except Exception as e:
                db.rollback()
                
                # CRITICAL FIX: Stock Rollback - attempt to return reserved stock if finalization fails.
                try:
                    db.execute('BEGIN IMMEDIATE TRANSACTION')
                    for item in temp_order['items']:
                        db.execute("UPDATE items SET stock = stock + ? WHERE name = ?", (item['quantity'], item['item_name']))
                    db.commit()
                    session.pop('temp_order')
                    # This error message is what the user sees when slot confirmation fails.
                    flash(f"ERROR: Order finalization failed. Reserved stock returned to inventory. Please select items and slot again. Details: {e}", "error")
                except Exception as rollback_error:
                    flash(f"FATAL ERROR: Order failed AND stock rollback failed. Admin intervention required. {rollback_error}", "error")
                    
                return redirect(url_for("book_items"))

        if error:
            flash(error, "error")
            return redirect(url_for("book_slot"))

    # GET REQUEST RENDERING
    slots = db.execute("""
        SELECT * FROM slots WHERE date_time > ? AND booked_count < capacity ORDER BY date_time
    """, (datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),)).fetchall()

    slots_html = ""
    for s in slots:
        dt = datetime.datetime.strptime(s['date_time'], '%Y-%m-%d %H:%M:%S')
        slots_html += f"""
        <label class="block p-4 border border-blue-300 rounded-xl hover:bg-blue-50 cursor-pointer transition duration-150 shadow-sm">
            <input type="radio" name="slot_id" value="{s['id']}" required class="mr-3 h-5 w-5 align-middle text-blue-600 focus:ring-blue-500">
            <span class="font-extrabold text-xl text-gray-800">{dt.strftime('%A, %d %b')}</span>
            <span class="font-extrabold text-2xl text-red-700 ml-4">{dt.strftime('%I:%M %p')}</span>
            <span class="text-sm text-gray-600 ml-4">({s['capacity'] - s['booked_count']} of {s['capacity']} slots left)</span>
        </label>
        """

    items_summary = ""
    for item in temp_order['items']:
        free_info = f" ({item['free_qty']:.1f} {item['unit']} FREE)" if item['free_qty'] > 0 else ""
        items_summary += f"""
        <li class="flex justify-between border-b pb-1">
            <span class="font-medium text-gray-700">{item['item_name']} ({item['quantity']:.1f} {item['unit']})</span>
            <span class="font-bold text-red-600">₹{item['cost']:.2f}{free_info}</span>
        </li>
        """

    content = f"""
    <div class="p-8 rounded-2xl shadow-2xl max-w-3xl mx-auto bg-white border-t-8 border-blue-600">
        <h3 class="text-3xl font-bold text-blue-900 mb-6 flex items-center gap-2"><span class="emoji-fix">2️⃣</span> Step 2: Review & Book Collection Slot</h3>
        
        <div class="bg-yellow-50 p-6 rounded-xl mb-6 border border-yellow-300 shadow-md">
            <p class="text-xl font-bold text-gray-800 mb-2">Total Amount Due (Cash on Delivery): <span class="text-3xl text-green-700 font-extrabold">₹{temp_order['total_cost']:.2f}</span></p>
            <p class="font-extrabold text-sm text-gray-700 mt-4 border-t pt-2">Items Reserved (Stock is Secured):</p>
            <ul class="list-none ml-2 space-y-2 text-sm pt-2">
                {items_summary}
            </ul>
        </div>
        
        <h4 class="text-2xl font-extrabold mb-4 text-gray-800 flex items-center gap-2"><span class="emoji-fix">⏰</span> Select Available Time Slot</h4>
        <form method="POST">
            <p class="text-md text-gray-600 mb-6">Choosing a slot finalizes your order and utilizes your monthly quota.</p>
            <div class="space-y-4">
                {slots_html if slots_html else '<p class="text-xl font-bold text-red-600 p-6 bg-red-50 rounded-xl border border-red-300">No available slots found. Check back tomorrow!</p>'}
            </div>
            <button type="submit" class="w-full bg-green-600 hover:bg-green-700 text-white font-extrabold py-4 px-4 rounded-xl transition duration-300 text-xl mt-8 shadow-lg transform hover:scale-[1.01]" {"disabled" if not slots_html else ""}>
                <span class="emoji-fix">✔️</span> Confirm Slot & Finalize Order
            </button>
            <p class="text-center text-sm mt-4"><a href="{url_for('cancel_order')}" class="text-red-600 font-semibold hover:underline">Cancel Booking & Release Stock Now</a></p>
        </form>
    </div>
    """
    return render_template_string(get_layout("Book Slot", content, 'user'))

@app.route("/cancel_order", methods=['GET'])
@login_required
def cancel_order():
    db = get_db()
    temp_order = session.pop('temp_order', None)
    
    if temp_order:
        try:
            db.execute('BEGIN TRANSACTION')
            for item in temp_order['items']:
                db.execute("UPDATE items SET stock = stock + ? WHERE name = ?", (item['quantity'], item['item_name']))
            db.commit()
            update_user_activity(g.user['card_number'], 'Cancelled Order')
            flash("Current order cancelled. Reserved stock returned to inventory.", "info")
        except Exception as e:
            db.rollback()
            flash(f"Error cancelling order and returning stock. Please notify admin. Error: {e}", "error")
    else:
        flash("No pending order to cancel.", "warning")
        
    return redirect(url_for('book_items'))

# ============================================================
# ADMIN ROUTES (STABILIZED)
# ============================================================

@app.route("/admin/login", methods=['GET', 'POST'])
def admin_login():
    db = get_db()
    error = None
    if request.method == 'POST':
        card_number = request.form['card_number'].strip().lower()
        password = request.form['password'].strip()
        user = db.execute("SELECT * FROM users WHERE card_number = ?", (card_number,)).fetchone()
        
        if not user or (user['is_admin'] != 1 and user['is_secondary_admin'] != 1):
            error = "Invalid admin credentials."
        elif not bcrypt.check_password_hash(user['password_hash'], password):
            error = "Invalid admin credentials."
        else:
            session['user_id'] = user['card_number']
            flash(f"Admin login successful. Welcome, {user['name']}.", "success")
            return redirect('/admin/dashboard')

    err_html = f"<div class='bg-red-100 border-l-4 border-red-500 text-red-700 p-3 mb-4 rounded-lg'><p>{error}</p></div>" if error else ""
    content = f"""
    <div class="bg-gray-800 p-8 rounded-2xl shadow-2xl max-w-md mx-auto text-white border-t-8 border-yellow-400">
        <h2 class="text-3xl font-extrabold mb-6 text-yellow-400 text-center">Admin Portal Login <span class="emoji-fix">👑</span></h2>
        {err_html}
        <div class="bg-gray-700 p-3 mb-4 rounded-lg text-sm text-center font-semibold border-2 border-dashed border-red-300">
            TEST ADMIN (ID: **admin**, Pass: **Admin@1**) | VIEW ADMIN (ID: **view**, Pass: **View@123**)
        </div>
        <form method="POST" class="space-y-4">
            <input name="card_number" placeholder="Admin ID (e.g., admin or view)" required class="border p-3 rounded-lg w-full bg-gray-700 text-white placeholder-gray-400 text-lg" value="{request.form.get('card_number', '')}">
            <div class="relative">
                <input type="password" id="admin-login-password" name="password" placeholder="Password" required class="border p-3 rounded-lg w-full bg-gray-700 text-white placeholder-gray-400 text-lg pr-10">
                <span class="absolute right-3 top-3 cursor-pointer emoji-fix text-gray-400" id="admin-login-password-toggle" onclick="togglePasswordVisibility('admin-login-password', 'admin-login-password-toggle')">👀</span>
            </div>
            <button class="bg-yellow-500 text-gray-900 px-4 py-4 rounded-xl w-full font-extrabold text-xl hover:bg-yellow-600 transition duration-150 shadow-lg">Login to Admin Portal</button>
        </form>
        <p class="text-sm text-gray-500 mt-6 text-center">Beneficiary Access: <a href="{url_for('login')}" class="text-blue-400 font-semibold hover:underline">User Login</a></p>
    </div>
    """
    return render_template_string(get_layout("Admin Login", content, 'guest'))

@app.route("/admin/dashboard")
@secondary_admin_required
def admin_dashboard():
    db = get_db()
    role = 'admin' if g.user['is_admin'] == 1 else 'secondary_admin'
    is_main_admin = g.user['is_admin'] == 1
    
    total_users = db.execute("SELECT COUNT(*) FROM users WHERE is_admin=0 AND is_secondary_admin=0").fetchone()[0] or 0
    pending_approval = db.execute("SELECT COUNT(*) FROM users WHERE is_approved=0 AND is_pre_registered=0").fetchone()[0] or 0
    
    today_date = datetime.date.today().isoformat()
    today_orders = db.execute("""
        SELECT COUNT(DISTINCT token) FROM orders
        WHERE order_date LIKE ? || '%' AND is_paid = 0
    """, (today_date,)).fetchone()[0] or 0
    
    pending_tokens = db.execute("SELECT COUNT(DISTINCT token) FROM orders WHERE is_paid = 0").fetchone()[0] or 0
    
    future_slots = db.execute("SELECT SUM(capacity) as total_capacity, SUM(booked_count) as total_booked FROM slots WHERE date_time > ?", (datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),)).fetchone()
    total_capacity = future_slots['total_capacity'] or 0
    total_booked = future_slots['total_booked'] or 0
    utilization_rate = (total_booked / total_capacity * 100) if total_capacity > 0 else 0

    low_stock_items = db.execute("SELECT name, stock, unit FROM items WHERE stock < 100 ORDER BY stock ASC").fetchall()
    
    sidebar_html = get_admin_sidebar_html(role, is_main_admin)
    
    summary = f"""
    <div class="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
        {get_stat_card("Total Beneficiaries", total_users, icon="👪", color="blue")}
        {get_stat_card("Pending Approvals", pending_approval, icon="📧", color="yellow")}
        {get_stat_card("Pending Collection Tokens", pending_tokens, icon="🛒", color="green")}
        {get_stat_card("Upcoming Slot Util.", f"{utilization_rate:.1f}%", icon="📈", color="red")}
    </div>
    
    <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div class="bg-white p-6 rounded-xl shadow-xl border-l-4 border-blue-500">
            <h4 class="text-xl font-extrabold mb-3 text-blue-900">Today's New Pending Orders</h4>
            <p class="text-5xl font-extrabold text-blue-600">{today_orders}</p>
            <p class="text-sm text-gray-500 mt-2">New orders placed today awaiting collection at a future slot.</p>
        </div>
        
        <div class="bg-white p-6 rounded-xl shadow-xl border-l-4 border-red-500">
            <h4 class="text-xl font-extrabold mb-3 text-red-900">Low Stock Alert (Stock < 100)</h4>
            <div class="space-y-2 max-h-32 overflow-y-auto">
            {("".join(f"<p class='text-sm font-semibold text-red-600'>{item['name']}: {item['stock']:.1f} {item['unit']}</p>" for item in low_stock_items)) if low_stock_items else "<p class='text-md text-green-600 font-semibold'>All stock levels are healthy.</p>"}
            </div>
            <a href="{url_for('admin_manage_items')}" class="bg-red-600 text-white px-4 py-2 rounded-lg block text-center mt-4 font-bold hover:bg-red-700 transition">MANAGE STOCK</a>
        </div>
    </div>
    """
    
    # --- FEATURE: Quick Action Bar on Admin Dashboard ---
    quick_actions_bar = f"""
    <div class="bg-gray-100 p-4 rounded-xl shadow-inner mb-6 border border-gray-300">
        <h4 class="text-lg font-extrabold mb-3 text-gray-800 flex items-center gap-2"><span class="emoji-fix">⚡</span> Quick Actions</h4>
        <div class="flex flex-wrap gap-3">
            <a href="{url_for('admin_manage_slots')}" class="bg-teal-600 text-white px-3 py-2 rounded-lg text-sm font-bold hover:bg-teal-700">🗓 Add Slot</a>
            <a href="{url_for('admin_manage_items')}" class="bg-yellow-600 text-white px-3 py-2 rounded-lg text-sm font-bold hover:bg-yellow-700">📦 Add Item/Stock</a>
            <a href="{url_for('admin_preregister')}" class="bg-blue-600 text-white px-3 py-2 rounded-lg text-sm font-bold hover:bg-blue-700">✍ Pre-register User</a>
            <a href="{url_for('admin_reports')}" class="bg-gray-600 text-white px-3 py-2 rounded-lg text-sm font-bold hover:bg-gray-700">📊 Run Full Report</a>
        </div>
    </div>
    """
    # --- END FEATURE ---

    content = f"""
    <div class="max-w-7xl mx-auto">
        <h2 class="text-3xl font-extrabold mb-6 text-blue-900">Welcome, {g.user['name']} <span class="text-sm text-gray-500">({role.replace('_', ' ').title()})</span></h2>
        
        {quick_actions_bar}
        
        <div class="flex flex-col md:flex-row gap-8">
            {sidebar_html}
            <div class="flex-grow">
                {summary}
            </div>
        </div>
    </div>
    """
    return render_template_string(get_layout("Admin Dashboard", content, role))

@app.route("/admin/preregister", methods=["GET", "POST"])
@secondary_admin_required
def admin_preregister():
    db = get_db()
    
    max_household_size = int(get_config('max_household_size', 10))
    PASSWORD_PATTERN = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+])[A-Za-z\d!@#$%^&*()_+]{6,8}$")

    if request.method == "POST":
        card_number = request.form.get("card_number", "").strip()
        full_name = request.form.get("name", "").strip()
        mobile = request.form.get("mobile", "").strip()
        member_count = request.form.get("member_count", "1").strip()
        password = request.form.get("password", "").strip()
        photo_file = request.files.get("photo")
        
        if not all([card_number, full_name, member_count]):
            flash("All required fields must be filled.", "error")
            return redirect(url_for("admin_preregister"))
            
        # 1. Card Number Validation (12 digits)
        if not re.match(r"^\d{12}$", card_number):
             flash("Invalid Card Number. Must be exactly **12 digits** (Numbers only).", "error")
             return redirect(url_for("admin_preregister"))
            
        # 2. Mobile Validation
        if mobile and not re.match(r"^\d{10}$", mobile):
             flash("Invalid mobile number. Must be 10 digits.", "error")
             return redirect(url_for("admin_preregister"))

        # 3. Member Count Validation
        try:
            member_count_val = int(member_count)
            if member_count_val < 1 or member_count_val > max_household_size:
                flash(f"Member count must be between 1 and {max_household_size}.", "error")
                return redirect(url_for("admin_preregister"))
        except ValueError:
            flash("Invalid value for member count.", "error")
            return redirect(url_for("admin_preregister"))
            
        # 4. Password Validation (New complex rules, max 8 chars)
        if not password:
             password = "Temporary@1" # Safe temporary password
             flash(f"No password provided, a temporary password ('{password}') has been assigned. Advise the user to change it.", "warning")

        if not PASSWORD_PATTERN.match(password):
             flash("Invalid Password. Must be 6-8 characters, including at least one uppercase, one lowercase, one number, and one special symbol (!@#$%^&*()_+).", "error")
             return redirect(url_for("admin_preregister"))

        
        existing_user = db.execute("SELECT card_number FROM users WHERE card_number = ?", (card_number,)).fetchone()
        if existing_user:
            flash(f"Card Number {card_number} already exists.", "error")
            return redirect(url_for("admin_preregister"))
            
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        photo_filename = None
        if photo_file and photo_file.filename:
            allowed_extensions = {'png', 'jpg', 'jpeg'}
            ext = os.path.splitext(photo_file.filename)[1].lower()
            if ext and ext[1:] in allowed_extensions:
                try:
                    unique_name = f"{card_number}_{uuid.uuid4().hex}{ext}"
                    save_path = os.path.join(UPLOAD_DIR, unique_name)
                    photo_file.save(save_path)
                    photo_filename = unique_name
                except Exception as e:
                    flash(f"Error uploading photo: {e}", "error")
                    return redirect(url_for("admin_preregister"))
            else:
                flash("Invalid photo file type. Only JPG, JPEG, PNG allowed.", "error")
                return redirect(url_for("admin_preregister"))
        
        try:
            db.execute("""
                INSERT INTO users (card_number, name, mobile_number, member_count, password_hash, photo_filename,
                                   is_pre_registered, is_approved, policy_accepted, last_activity_date)
                VALUES (?, ?, ?, ?, ?, ?, 1, 1, 1, ?)
            """, (card_number, full_name, mobile, member_count_val, hashed_password, photo_filename, datetime.datetime.now().isoformat()))
            db.commit()
            
            flash(f"Pre-registration successful! Card Number: **{card_number}**. The user can now log in using the temporary password.", "success")
            return redirect(url_for("admin_preregister"))

        except Exception as e:
            db.rollback()
            flash(f"An unexpected error occurred during database insert: {e}", "error")
            return redirect(url_for("admin_preregister"))
            
    max_household_size = int(get_config('max_household_size', 10))
    role = 'admin' if g.user['is_admin']==1 else 'secondary_admin'
    sidebar_html = get_admin_sidebar_html(role, g.user['is_admin']==1)
    
    # Client-side validation script - Reused logic from public register, adapted slightly.
    password_check_script = """
    <script>
        function checkPasswordStrengthAdmin(password) {
            const requirements = [
                { pattern: /.{6,8}/, message: "Length 6-8 characters" },
                { pattern: /[A-Z]/, message: "One Uppercase letter" },
                { pattern: /[a-z]/, message: "One Lowercase letter" },
                { pattern: /\d/, message: "One Number" },
                { pattern: /[!@#$%^&*()_+]/, message: "One Special Symbol (!@#$%^&*()_+)" }
            ];
            const feedbackElement = document.getElementById('admin-password-feedback');
            let html = '';

            requirements.forEach(req => {
                const passed = req.pattern.test(password);
                const color = passed ? 'text-green-600' : 'text-red-600';
                const icon = passed ? '✅' : '❌';
                html += `<li class="${color}">${icon} ${req.message}</li>`;
            });

            feedbackElement.innerHTML = `<ul class="list-none space-y-1">${html}</ul>`;
        }
    </script>
    """
    
    content = f"""
    <div class="flex flex-col md:flex-row gap-6 max-w-7xl mx-auto">
        {sidebar_html}
        <div class="flex-grow bg-white p-8 rounded-2xl shadow-2xl border-t-8 border-blue-600">
            <h2 class="text-3xl font-bold mb-6 text-blue-900 flex items-center gap-2"><span class="emoji-fix">✍️</span> Pre-register New Beneficiary</h2>
            <p class="text-gray-600 mb-6 text-lg">Use this form for in-person registration to grant immediate, approved access to the system.</p>
            <form method="POST" enctype="multipart/form-data" class="grid grid-cols-1 md:grid-cols-2 gap-6">
                <input name="card_number" placeholder="Card Number (12 digits only)" required class="border p-3 rounded-lg w-full text-lg" pattern="\\d{{12}}" title="Card number must be exactly 12 digits" maxlength="12" value="{request.form.get('card_number', '')}">
                <input name="name" placeholder="Full Name" required class="border p-3 rounded-lg w-full text-lg" value="{request.form.get('name', '')}">
                <input name="mobile" placeholder="Mobile Number (10 digits, Optional)" class="border p-3 rounded-lg w-full text-lg" pattern="\\d{{10}}" maxlength="10" value="{request.form.get('mobile', '')}">
                <input name="member_count" type="number" min="1" max="{max_household_size}" value="{request.form.get('member_count', '1')}" placeholder="Household Member Count (Max: {max_household_size})" required class="border p-3 rounded-lg w-full text-lg">
                <div class="md:col-span-2">
                    <label class="text-lg text-gray-700 block mb-1 font-semibold">Upload Card Holder Photo (JPG/PNG)</label>
                    <input type="file" name="photo" accept=".jpg,.jpeg,.png" class="border p-3 rounded-lg w-full bg-gray-50">
                </div>
                <div class="md:col-span-2">
                    <div class="relative">
                        <input type="password" id="admin-prereg-password" name="password" placeholder="Temporary Password (6-8 chars, complex rules, optional)" class="border p-3 rounded-lg w-full text-lg pr-10" onkeyup="checkPasswordStrengthAdmin(this.value)">
                        <span class="absolute right-3 top-3 cursor-pointer emoji-fix" id="admin-prereg-password-toggle" onclick="togglePasswordVisibility('admin-prereg-password', 'admin-prereg-password-toggle')">👀</span>
                    </div>
                    
                    <div id="admin-password-feedback" class="bg-gray-50 p-3 rounded-lg border text-sm mt-2">
                        <p class="font-bold text-gray-700 mb-1">Password Requirements (6-8 Chars):</p>
                        <ul class="list-none space-y-1">
                            <li class="text-red-600">❌ Length 6-8 characters</li>
                            <li class="text-red-600">❌ One Uppercase letter</li>
                            <li class="text-red-600">❌ One Lowercase letter</li>
                            <li class="text-red-600">❌ One Number</li>
                            <li class="text-red-600">❌ One Special Symbol (!@#$%^&*()_+)</li>
                        </ul>
                    </div>
                </div>
                <div class="md:col-span-2">
                    <button class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-4 rounded-xl mt-4 w-full font-extrabold text-xl transition duration-150 shadow-lg">Pre-register & Approve User</button>
                </div>
            </form>
        </div>
    </div>
    {password_check_script}
    """
    return render_template_string(get_layout("Admin: Pre-register", content, role))

@app.route("/admin/quota_check", methods=['GET', 'POST'])
@secondary_admin_required
def admin_quota_check():
    db = get_db()
    user_quota_data = None
    error = None

    if request.method == 'POST':
        card_number = request.form.get("card_number", "").strip()
        
        # New 12-digit card validation
        if not re.match(r"^\d{12}$", card_number):
            error = "Invalid Card Number. Must be exactly **12 digits** (Numbers only)."
        else:
            user = db.execute("SELECT * FROM users WHERE card_number = ? AND is_admin = 0 AND is_secondary_admin = 0", (card_number,)).fetchone()
            
            if user:
                update_user_activity(g.user['card_number'], f'Checked Quota for {card_number}')
                
                max_rice = float(get_config('max_free_rice_kg', 30))
                max_wheat = float(get_config('max_free_wheat_kg', 25))
                
                user_quota_data = {
                    'name': user['name'],
                    'card_number': user['card_number'],
                    'status': 'Approved' if user['is_approved'] == 1 else 'Pending',
                    'is_blocked': user['is_blocked'] == 1,
                    'rice_collected': user['monthly_collected_kg_rice'],
                    'rice_max': max_rice,
                    'rice_remaining': max(0.0, max_rice - user['monthly_collected_kg_rice']),
                    'wheat_collected': user['monthly_collected_kg_wheat'],
                    'wheat_max': max_wheat,
                    'wheat_remaining': max(0.0, max_wheat - user['monthly_collected_kg_wheat']),
                }
            else:
                error = f"Beneficiary with Card Number **{card_number}** not found or is an admin account."

    err_html = f'<div class="bg-red-100 border-l-4 border-red-500 text-red-700 p-3 mb-4 rounded-lg"><p>{error}</p></div>' if error else ""
    
    quota_result_html = ""
    if user_quota_data:
        quota_result_html = f"""
        <div class="bg-blue-50 p-6 rounded-xl shadow-xl border-t-8 border-purple-600">
            <h4 class="text-2xl font-extrabold text-purple-800 mb-4 flex items-center gap-2"><span class="emoji-fix">📊</span> Quota for {user_quota_data['name']}</h4>
            <p class="text-lg mb-4">Card: **{user_quota_data['card_number']}** | Status: <span class="font-bold text-{'red' if user_quota_data['is_blocked'] else 'green'}-600">{user_quota_data['status']}{' - BLOCKED 🛑' if user_quota_data['is_blocked'] else ''}</span></p>

            <h5 class="font-bold text-xl text-gray-800 border-b pb-1 mt-4">Rice Quota (Current Month)</h5>
            <p class="text-lg mt-2">Collected: **{user_quota_data['rice_collected']:.1f} kg** / Max Free: {user_quota_data['rice_max']:.1f} kg</p>
            <p class="text-2xl font-extrabold text-green-700">Remaining Free: **{user_quota_data['rice_remaining']:.1f} kg**</p>
            
            <h5 class="font-bold text-xl text-gray-800 border-b pb-1 mt-6">Wheat Quota (Current Month)</h5>
            <p class="text-lg mt-2">Collected: **{user_quota_data['wheat_collected']:.1f} kg** / Max Free: {user_quota_data['wheat_max']:.1f} kg</p>
            <p class="text-2xl font-extrabold text-green-700">Remaining Free: **{user_quota_data['wheat_remaining']:.1f} kg**</p>
            
            <p class="text-sm text-gray-600 mt-4">Last Reset: {get_config('last_reset_date', 'N/A')}</p>
        </div>
        """
    
    role = 'admin' if g.user['is_admin'] == 1 else 'secondary_admin'
    sidebar_html = get_admin_sidebar_html(role, g.user['is_admin']==1)
    
    content = f"""
    <div class="flex flex-col md:flex-row gap-8 max-w-7xl mx-auto">
        {sidebar_html}
        <div class="flex-grow">
            <h2 class="text-3xl font-bold mb-6 text-blue-900">Beneficiary Quota Check Utility</h2>
            {err_html}
            
            <div class="bg-white p-6 rounded-xl shadow-xl max-w-xl mb-8 border-t-4 border-purple-600">
                <h3 class="text-xl font-bold text-purple-800 mb-4">Search by Card Number</h3>
                <form method="POST">
                    <div class="flex gap-4">
                        <input type="text" name="card_number" placeholder="Enter Card Number (12 digits)" required class="flex-grow px-3 py-3 border rounded-lg font-mono text-lg" pattern="\\d{{12}}" title="Card number must be exactly 12 digits" maxlength="12" value="{request.form.get('card_number', '')}">
                        <button class="bg-purple-600 text-white px-4 py-3 rounded-lg hover:bg-purple-700 font-bold">Check Quota</button>
                    </div>
                </form>
            </div>
            
            {quota_result_html}
        </div>
    </div>
    """
    return render_template_string(get_layout("Admin: Quota Check", content, role))

@app.route("/admin/token_validation", methods=['GET', 'POST'])
@secondary_admin_required
def admin_token_validation():
    db = get_db()
    error = None
    message = None
    order_data = None
    
    if request.method == 'POST':
        action = request.form['action']
        token = request.form.get('token', '').strip().upper()
        
        if action == 'search':
            if not token or not re.match(r"^[A-Z0-9]{6}$", token):
                error = "Please enter a valid 6-character collection token."
            else:
                order_items = db.execute("""
                    SELECT o.*, u.name, u.card_number, u.is_blocked, s.date_time, i.unit, i.unit_price
                    FROM orders o
                    JOIN users u ON o.card_number = u.card_number
                    JOIN slots s ON o.slot_id = s.id
                    JOIN items i ON o.item_name = i.name
                    WHERE o.token = ? AND o.is_paid = 0
                """, (token,)).fetchall()
                
                if order_items:
                    # --- FEATURE: Check Blocked Status Immediately ---
                    is_blocked = order_items[0]['is_blocked'] == 1
                    if is_blocked:
                         error = f"Token {token} found, but the card holder ({order_items[0]['card_number']}) is **BLOCKED** from receiving rations. Fulfillment is prevented."
                         flash(error, "error")
                         order_data = None
                         return redirect(url_for("admin_token_validation"))
                    # --- END FEATURE ---
                    
                    total_cost = sum(item['total_cost'] for item in order_items)
                    
                    # --- Determine collection window status ---
                    slot_time_str = order_items[0]['date_time']
                    slot_dt = datetime.datetime.strptime(slot_time_str, '%Y-%m-%d %H:%M:%S')
                    now = datetime.datetime.now()
                    
                    # Assume a 1-hour collection window starting at slot_dt
                    is_too_early = now < slot_dt
                    is_too_late = now > (slot_dt + datetime.timedelta(hours=1))
                    
                    if is_too_early:
                        collection_status = f"<span class='text-yellow-600 font-extrabold'>EARLY!</span> Please advise user to return at {slot_dt.strftime('%I:%M %p')}."
                    elif is_too_late:
                        collection_status = f"<span class='text-red-600 font-extrabold'>LATE!</span> Slot expired {int((now - slot_dt).total_seconds() / 60)} minutes ago. (Order should ideally be cancelled)"
                    else:
                        collection_status = f"<span class='text-green-600 font-extrabold'>ON TIME!</span> Collection window is open."
                    
                    # Calculate rice/wheat collection info for the progress bar
                    total_free_rice_ordered = sum(item['free_qty'] for item in order_items if item['item_name'] == 'Rice')
                    total_free_wheat_ordered = sum(item['free_qty'] for item in order_items if item['item_name'] == 'Wheat')
                    
                    user_row = db.execute("SELECT monthly_collected_kg_rice, monthly_collected_kg_wheat FROM users WHERE card_number = ?", (order_items[0]['card_number'],)).fetchone()
                    
                    max_rice_config = float(get_config('max_free_rice_kg', 30))
                    max_wheat_config = float(get_config('max_free_wheat_kg', 25))
                    
                    new_rice_collected = user_row['monthly_collected_kg_rice'] + total_free_rice_ordered
                    new_wheat_collected = user_row['monthly_collected_kg_wheat'] + total_free_wheat_ordered
                    
                    rice_percent = int((new_rice_collected / max_rice_config) * 100) if max_rice_config > 0 else 0
                    wheat_percent = int((new_wheat_collected / max_wheat_config) * 100) if max_wheat_config > 0 else 0
                    rice_percent = min(100, rice_percent)
                    wheat_percent = min(100, wheat_percent)
                    
                    order_data = {
                        'token': token,
                        'name': order_items[0]['name'],
                        'card_number': order_items[0]['card_number'],
                        'slot_time': slot_dt.strftime('%A, %d %b %Y at %I:%M %p'),
                        'items': order_items,
                        'total_cost': total_cost,
                        'collection_status': collection_status,
                        'rice_percent': rice_percent,
                        'wheat_percent': wheat_percent,
                        'new_rice_collected': new_rice_collected,
                        'new_wheat_collected': new_wheat_collected,
                        'max_rice_config': max_rice_config,
                        'max_wheat_config': max_wheat_config
                    }
                    message = f"Order **{token}** found for **{order_data['name']}**. Total due: ₹{total_cost:.2f}. Ready for collection."
                else:
                    already_paid = db.execute("SELECT token FROM orders WHERE token = ? AND is_paid = 1", (token,)).fetchone()
                    if already_paid:
                        error = f"Token {token} has already been collected and paid. Cannot re-fulfill."
                    else:
                        error = f"Token {token} not found or is not pending collection."
        
        elif action == 'fulfill':
            if not re.match(r"^[A-Z0-9]{6}$", token):
                error = "Invalid token format."
            else:
                try:
                    pending = db.execute("SELECT COUNT(*) FROM orders WHERE token = ? AND is_paid = 0", (token,)).fetchone()[0]
                    if pending == 0:
                        error = f"Token {token} was already fulfilled by another admin."
                    else:
                        db.execute('UPDATE orders SET is_paid = 1 WHERE token = ?', (token,))
                        db.commit()
                        update_user_activity(g.user['card_number'], f'Fulfilled Token {token}')
                        flash(f"Order **{token}** successfully fulfilled (collected and marked as paid).", "success")
                        return redirect(url_for("admin_token_validation"))

                except sqlite3.Error as e:
                    db.rollback()
                    error = f"Database Error fulfilling order: {e}"
                except Exception as e:
                    error = f"Error fulfilling order: {e}"
                
        if error:
            flash(error, "error")
            
    role = 'admin' if g.user['is_admin'] == 1 else 'secondary_admin'
    sidebar_html = get_admin_sidebar_html(role, g.user['is_admin']==1)
    
    form_content = f"""
    <div class="bg-white p-8 rounded-2xl shadow-xl max-w-xl mb-8 border-t-8 border-red-600">
        <h3 class="text-2xl font-bold text-red-800 mb-4 flex items-center gap-2"><span class="emoji-fix">🔍</span> Order Token Validation</h3>
        <p class="text-gray-600 mb-4 text-lg">Enter the unique collection token provided by the user to verify the order details.</p>
        <form method="POST">
            <input type="hidden" name="action" value="search">
            <div class="flex gap-4">
                <input type="text" name="token" placeholder="Enter Token (e.g., F2B6D4)" required class="flex-grow px-3 py-3 border rounded-lg uppercase font-mono text-lg" pattern="[A-Z0-9]{{6}}" title="Token must be exactly 6 uppercase letters/numbers" maxlength="6" value="{request.form.get('token', '').strip().upper()}">
                <button class="bg-blue-600 text-white px-4 py-3 rounded-xl hover:bg-blue-700 font-bold shadow-md">Search Token</button>
            </div>
        </form>
    </div>
    """

    order_details_html = ""
    if order_data:
        items_list = ""
        for item in order_data['items']:
            free_info = f"<span class='text-green-700 font-semibold'>({item['free_qty']:.1f} {item['unit']} FREE)</span>" if item['free_qty'] > 0 else ""
            items_list += f"""
            <li class="flex justify-between border-b py-2 text-md">
                <span>**{item['item_name']}** - {item['quantity']:.1f} {item['unit']} </span>
                <span class="font-bold text-gray-800">₹{item['total_cost']:.2f} {free_info}</span>
            </li>
            """
        
        # --- Quota Progress Bars ---
        quota_bars = f"""
        <h5 class="font-extrabold text-xl mt-6 mb-3 border-t pt-2">Quota Impact & Collection Window</h5>
        <p class="text-md mb-2">Collection Window Status: {order_data['collection_status']}</p>

        <div class="mb-4">
            <p class="text-sm font-semibold text-gray-800">Rice Quota (Post-Collection Est.): {order_data['new_rice_collected']:.1f} kg / {order_data['max_rice_config']:.1f} kg</p>
            <div class="w-full bg-gray-200 rounded-full h-3">
                <div class="bg-green-600 h-3 rounded-full" style="width: {order_data['rice_percent']}%;"></div>
            </div>
        </div>
        
        <div class="mb-4">
            <p class="text-sm font-semibold text-gray-800">Wheat Quota (Post-Collection Est.): {order_data['new_wheat_collected']:.1f} kg / {order_data['max_wheat_config']:.1f} kg</p>
            <div class="w-full bg-gray-200 rounded-full h-3">
                <div class="bg-green-600 h-3 rounded-full" style="width: {order_data['wheat_percent']}%;"></div>
            </div>
        </div>
        """
        # --- End Quota Progress Bars ---
        
        order_details_html = f"""
        <div class="bg-yellow-50 p-8 rounded-2xl shadow-2xl max-w-xl mx-auto border-t-8 border-orange-600">
            <h4 class="text-2xl font-bold mb-4 text-orange-800 flex items-center gap-2"><span class="emoji-fix">✅</span> Pending Order Details: <span class="text-red-700">{order_data['token']}</span></h4>
            <p class="text-lg">User: <strong>{order_data['name']}</strong> ({order_data['card_number']})</p>
            <p class="text-lg mb-4">Slot Time: <strong class="text-red-700 font-bold">{order_data['slot_time']}</strong></p>
            
            {quota_bars}
            
            <h5 class="font-extrabold text-xl mt-4 mb-2 border-t pt-2">Items for Collection:</h5>
            <ul class="list-none mb-4 space-y-2">{items_list}</ul>
            
            <div class="flex justify-between items-center border-t-4 border-dashed pt-4">
                <p class="text-2xl font-extrabold">TOTAL DUE (COD)</p>
                <p class="text-4xl font-extrabold text-green-700">₹{order_data['total_cost']:.2f}</p>
            </div>
            
            <form method="POST" class="mt-6" onsubmit="return confirm('Confirm fulfillment of token {order_data['token']}? This marks the order as collected/paid.');">
                <input type="hidden" name="action" value="fulfill">
                <input type="hidden" name="token" value="{order_data['token']}">
                <button class="w-full bg-green-600 text-white px-4 py-4 rounded-xl font-extrabold text-xl hover:bg-green-700 shadow-lg transform hover:scale-[1.01]">Confirm Collection & Fulfill Order</button>
            </form>
        </div>
        """

    content = f"""
    <div class="flex flex-col md:flex-row gap-8 max-w-7xl mx-auto">
        {sidebar_html}
        <div class="flex-grow">
            <h2 class="text-3xl font-bold mb-6 text-blue-900">Token Validation & Fulfillment</h2>
            
            <div class="flex flex-col md:flex-row gap-6">
                <div class="md:w-full">
                    {form_content}
                </div>
            </div>
            {order_details_html}
        </div>
    </div>
    """
    return render_template_string(get_layout("Admin: Token Validation", content, role))

@app.route("/admin/manage_users", methods=['GET', 'POST'])
@secondary_admin_required
def admin_manage_users():
    db = get_db()
    error = None
    message = None
    is_main_admin = g.user['is_admin'] == 1
    
    # --- FEATURE: User Search/Filter ---
    search_query = request.args.get('search', '').strip().upper()
    search_filter = ""
    if search_query:
        search_filter = f"AND (card_number LIKE '%{search_query}%' OR name LIKE '%{search_query}%')"
    # --- END FEATURE ---

    if request.method == 'POST':
        action = request.form.get('action')
        card_number = request.form.get('card_number', '').strip()
        
        if card_number in ('admin', 'view') and card_number != g.user['card_number']:
             if not is_main_admin:
                 flash("Permission denied. You cannot modify main admin accounts.", "error")
                 return redirect(url_for("admin_manage_users"))

        try:
            if action == 'approve':
                db.execute('UPDATE users SET is_approved = 1, is_pre_registered = 0, policy_accepted = 0 WHERE card_number = ?', (card_number,))
                db.commit()
                message = f"User **{card_number}** approved. They must accept the policy upon first login."
            elif action == 'block':
                db.execute('UPDATE users SET is_blocked = 1 WHERE card_number = ?', (card_number,))
                db.commit()
                message = f"User **{card_number}** blocked. They can no longer log in."
            elif action == 'unblock':
                db.execute('UPDATE users SET is_blocked = 0 WHERE card_number = ?', (card_number,))
                db.commit()
                message = f"User **{card_number}** unblocked."
            elif action == 'delete':
                if not is_main_admin:
                    raise Exception("Only the Main Admin can delete users.")
                db.execute('DELETE FROM users WHERE card_number = ?', (card_number,))
                db.execute('DELETE FROM orders WHERE card_number = ?', (card_number,))
                db.commit()
                message = f"User **{card_number}** and all related orders permanently deleted."
            else:
                error = "Invalid action."
                
            if message: flash(message, "success")
            if error: flash(error, "error")

        except Exception as e:
            db.rollback()
            flash(f"Operation failed: {e}", "error")
            
        # Redirect, preserving the search query if one exists
        return redirect(url_for("admin_manage_users", search=request.args.get('search', '')))

    users = db.execute(f"SELECT * FROM users WHERE is_admin = 0 AND is_secondary_admin = 0 {search_filter} ORDER BY is_approved, name").fetchall()
    
    users_html = ""
    for u in users:
        status = "Pending Approval" if u['is_approved'] == 0 else "Approved"
        status_color = "text-yellow-600 font-bold" if u['is_approved'] == 0 else "text-green-600"
        blocked = " • BLOCKED 🛑" if u['is_blocked'] == 1 else ""
        
        photo_badge = get_user_photo_display(u)
        
        actions = ""
        if u['is_approved'] == 0:
            actions += f"""
            <form method="POST" class="inline-block" onsubmit="return confirm('Approve {u['card_number']}?');">
                <input type="hidden" name="action" value="approve">
                <input type="hidden" name="card_number" value="{u['card_number']}">
                <button class="bg-green-600 text-white px-3 py-2 rounded-xl text-sm font-bold hover:bg-green-700">Approve</button>
            </form>
            """
        
        if u['is_blocked'] == 0:
            actions += f"""
            <form method="POST" class="inline-block" onsubmit="return confirm('Block {u['card_number']}? This revokes login access.');">
                <input type="hidden" name="action" value="block">
                <input type="hidden" name="card_number" value="{u['card_number']}">
                <button class="bg-red-600 text-white px-3 py-2 rounded-xl text-sm font-bold hover:bg-red-700">Block</button>
            </form>
            """
        else:
            actions += f"""
            <form method="POST" class="inline-block">
                <input type="hidden" name="action" value="unblock">
                <input type="hidden" name="card_number" value="{u['card_number']}">
                <button class="bg-yellow-600 text-white px-3 py-2 rounded-xl text-sm font-bold hover:bg-yellow-700">Unblock</button>
            </form>
            """
        
        actions += f"""
        <a href="{url_for('admin_edit_user', card_number=u['card_number'])}" class="bg-blue-600 text-white px-3 py-2 rounded-xl text-sm font-bold hover:bg-blue-700">Edit</a>
        """
        
        if is_main_admin:
            actions += f"""
            <form method="POST" class="inline-block" onsubmit="return confirm('Permanently DELETE user {u['card_number']} and ALL orders? This is irreversible.');">
                <input type="hidden" name="action" value="delete">
                <input type="hidden" name="card_number" value="{u['card_number']}">
                <button class="bg-gray-400 text-gray-800 px-3 py-2 rounded-xl text-sm font-bold hover:bg-gray-500">Delete</button>
            </form>
            """

        users_html += f"""
        <div class="bg-white p-5 rounded-xl shadow-lg mb-4 border-l-8 border-{'yellow' if u['is_approved']==0 else 'green'}-600">
            <div class="flex justify-between items-center">
                <div class="flex items-center">
                    {photo_badge}
                    <div>
                        <p class="font-extrabold text-xl">{u['name']} ({u['card_number']})</p>
                        <p class="text-xs text-gray-600">Type: {u['card_type'] or 'N/A'} | Members: {u['member_count']} | Status: <span class="{status_color}">{status}</span>{blocked}</p>
                    </div>
                </div>
                <div class="flex gap-2 flex-wrap justify-end">{actions}</div>
            </div>
        </div>
        """
    
    role = 'admin' if g.user['is_admin'] == 1 else 'secondary_admin'
    sidebar_html = get_admin_sidebar_html(role, is_main_admin)

    content = f"""
    <div class="flex flex-col md:flex-row gap-8 max-w-7xl mx-auto">
        {sidebar_html}
        <div class="flex-grow">
            <h2 class="text-3xl font-bold mb-6 text-blue-900">Manage Beneficiary Accounts & Verification</h2>
            
            <div class="bg-gray-100 p-4 rounded-xl shadow-inner mb-6 border border-gray-300">
                <h3 class="text-xl font-bold text-blue-800 mb-4 flex items-center gap-2"><span class="emoji-fix">🔎</span> Search Users</h3>
                <form method="GET">
                    <div class="flex gap-4">
                        <input type="text" name="search" placeholder="Search by Card Number (12 digits) or Name" 
                               class="flex-grow px-3 py-3 border rounded-lg text-lg uppercase" 
                               value="{request.args.get('search', '')}">
                        <button class="bg-blue-600 text-white px-4 py-3 rounded-lg hover:bg-blue-700 font-bold">Search</button>
                    </div>
                    {f'<p class="text-sm mt-2 text-gray-600">Showing {len(users)} results for: **{search_query}**</p>' if search_query else f'<p class="text-sm mt-2 text-gray-600">Total Users: **{len(users)}**</p>'}
                </form>
            </div>
            
            {users_html if users_html else "<p class='text-xl font-bold text-gray-600 p-6 bg-gray-100 rounded-xl border border-gray-300'>No non-admin beneficiaries found matching your query.</p>"}
        </div>
    </div>
    """
    return render_template_string(get_layout("Admin: Manage Users", content, role))


@app.route("/admin/edit_user/<card_number>", methods=['GET', 'POST'])
@admin_required
def admin_edit_user(card_number):
    db = get_db()
    user_to_edit = db.execute('SELECT * FROM users WHERE card_number = ? AND is_admin = 0 AND is_secondary_admin = 0', (card_number,)).fetchone()
    
    if user_to_edit is None:
        flash("Beneficiary user not found or is an Admin/Secondary Admin.", "error")
        return redirect(url_for('admin_manage_users'))
    
    error = None
    max_household_size = int(get_config('max_household_size', 10))
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        try:
            if action == 'update_details':
                name = request.form.get('name', user_to_edit['name']).strip()
                card_type = request.form.get('card_type', user_to_edit['card_type'] or '').strip().upper()
                mobile_number = request.form.get('mobile_number', user_to_edit['mobile_number'] or '').strip()
                address = request.form.get('address', user_to_edit['address'] or '').strip()
                member_count = request.form.get('member_count', str(user_to_edit['member_count'])).strip()
                
                member_count_val = int(member_count)
                if member_count_val < 1 or member_count_val > max_household_size:
                    raise ValueError(f"Member count must be between 1 and {max_household_size}.")
                
                if mobile_number and not re.match(r"^\d{10}$", mobile_number):
                    raise ValueError("Invalid mobile number format.")
                    
                db.execute("""
                    UPDATE users SET name=?, card_type=?, mobile_number=?, address=?, member_count=?
                    WHERE card_number=?
                """, (name, card_type, mobile_number, address, member_count_val, card_number))
                db.commit()
                flash("User details updated successfully.", "success")
                
            elif action == 'reset_password':
                new_password = request.form['new_password']
                # Re-check the password complexity here for admin-forced reset
                PASSWORD_PATTERN = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+])[A-Za-z\d!@#$%^&*()_+]{6,8}$")
                if not PASSWORD_PATTERN.match(new_password):
                    raise ValueError("New password must be 6-8 characters, with at least one uppercase, lowercase, number, and special symbol.")
                    
                password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
                db.execute('UPDATE users SET password_hash = ? WHERE card_number = ?', (password_hash, card_number))
                db.commit()
                flash("Password reset successfully. User must use the new password to log in.", "success")
            
            elif action == 'update_quota':
                rice_collected = float(request.form['monthly_collected_kg_rice'])
                wheat_collected = float(request.form['monthly_collected_kg_wheat'])
                
                if rice_collected < 0 or wheat_collected < 0:
                    raise ValueError("Collected quotas cannot be negative.")
                    
                db.execute("""
                    UPDATE users SET monthly_collected_kg_rice = ?, monthly_collected_kg_wheat = ?
                    WHERE card_number = ?
                """, (rice_collected, wheat_collected, card_number))
                db.commit()
                flash("Monthly quota balance updated.", "success")
            
            else:
                error = "Invalid action."
                
            user_to_edit = db.execute('SELECT * FROM users WHERE card_number = ?', (card_number,)).fetchone()
            
        except ValueError as e:
            error = f"Input Error: {e}"
            flash(error, "error")
        except Exception as e:
            db.rollback()
            error = f"Unexpected error: {e}"
            flash(error, "error")
            
        return redirect(url_for('admin_edit_user', card_number=card_number))
    
    user_to_edit = db.execute('SELECT * FROM users WHERE card_number = ?', (card_number,)).fetchone()

    photo_preview = f"""
    <img src='{url_for('uploads', filename=user_to_edit['photo_filename'])}'
    class='h-24 w-24 rounded-full object-cover border-4 border-blue-600 shadow-lg' alt="User Photo">
    """ if user_to_edit['photo_filename'] else f"""
    <div class='h-24 w-24 rounded-full bg-blue-600 flex items-center justify-center text-4xl font-bold text-white border-4 border-blue-600 shadow-lg'>{get_user_initials(user_to_edit['name'])}</div>
    """
    
    sidebar_html = get_admin_sidebar_html(g.user['card_number'], g.user['is_admin']==1)

    content = f"""
    <div class="flex flex-col md:flex-row gap-8 max-w-7xl mx-auto">
        {sidebar_html}
        <div class="flex-grow">
            <h3 class="text-3xl font-bold mb-6 text-blue-900">Edit User: {user_to_edit['name']} ({card_number})</h3>
            <a href="{url_for('admin_manage_users')}" class="text-blue-600 hover:underline mb-4 inline-block font-semibold flex items-center gap-1"><span class="emoji-fix">⬅️</span> Back to Users</a>
            
            <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                
                <div class="bg-white p-6 rounded-xl shadow-xl border-l-8 border-blue-600">
                    <h4 class="text-xl font-extrabold mb-4 text-blue-800">Edit Details</h4>
                    <div class="flex items-center gap-3 mb-4 border-b pb-4">
                        {photo_preview}
                        <div>
                            <p class="text-md font-bold">Status: <span class="text-green-600">{'Approved' if user_to_edit['is_approved'] == 1 else 'Pending'}</span></p>
                            <p class="text-md font-bold">Card Type: {user_to_edit['card_type'] or 'N/A'}</p>
                        </div>
                    </div>
                    <form method="POST">
                        <input type="hidden" name="action" value="update_details">
                        <label class="block text-gray-700 font-bold mb-1">Full Name</label>
                        <input type="text" name="name" value="{user_to_edit['name']}" required class="w-full px-3 py-2 border rounded-lg mb-3 text-lg">
                        <label class="block text-gray-700 font-bold mb-1">Card Type (APL/BPL)</label>
                        <input type="text" name="card_type" value="{user_to_edit['card_type'] or ''}" required class="w-full px-3 py-2 border rounded-lg mb-3 text-lg uppercase">
                        <label class="block text-gray-700 font-bold mb-1">Mobile Number</label>
                        <input type="text" name="mobile_number" value="{user_to_edit['mobile_number'] or ''}" class="w-full px-3 py-2 border rounded-lg mb-3 text-lg" placeholder="10 digits" pattern="\\d{{10}}" maxlength="10">
                        <label class="block text-gray-700 font-bold mb-1">Member Count (Max {max_household_size})</label>
                        <input type="number" min="1" max="{max_household_size}" name="member_count" value="{user_to_edit['member_count']}" required class="w-full px-3 py-2 border rounded-lg mb-3 text-lg">
                        <label class="block text-gray-700 font-bold mb-1">Address</label>
                        <textarea name="address" class="w-full px-3 py-2 border rounded-lg mb-4 text-lg h-24">{user_to_edit['address'] or ''}</textarea>
                        <button class="w-full bg-blue-600 text-white px-4 py-3 rounded-xl font-bold hover:bg-blue-700 shadow-md">Save Details</button>
                    </form>
                </div>
                
                <div class="space-y-6">
                    <div class="bg-white p-6 rounded-xl shadow-xl border-l-8 border-red-600">
                        <h4 class="text-xl font-extrabold mb-4 text-red-700">Reset Password (Admin Only)</h4>
                        <form method="POST">
                            <input type="hidden" name="action" value="reset_password">
                            <label class="block text-gray-700 font-bold mb-1">New Password (6-8 chars, complex rules)</label>
                            <div class="relative">
                                <input type="password" id="edit-password" name="new_password" required class="w-full px-3 py-2 border rounded-lg mb-4 text-lg pr-10" pattern="^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[!@#$%^&*()_+])[A-Za-z\\d!@#$%^&*()_+]{6,8}$" title="Password must be 6-8 chars, with at least one uppercase, lowercase, number, and special symbol">
                                <span class="absolute right-3 top-2 cursor-pointer emoji-fix" id="edit-password-toggle" onclick="togglePasswordVisibility('edit-password', 'edit-password-toggle')">👀</span>
                            </div>
                            <button class="w-full bg-red-600 text-white px-4 py-3 rounded-xl font-bold hover:bg-red-700 shadow-md" onclick="return confirm('ADMIN WARNING: Are you sure you want to reset the password for {card_number}?');">Force Reset Password</button>
                        </form>
                    </div>
                    
                    <div class="bg-white p-6 rounded-xl shadow-xl border-l-8 border-green-600">
                        <h4 class="text-xl font-extrabold mb-4 text-green-800">Adjust Monthly Quota Balance</h4>
                        <form method="POST">
                            <input type="hidden" name="action" value="update_quota">
                            <label class="block text-gray-700 font-bold mb-1">Rice Collected This Month (kg)</label>
                            <input type="number" step="0.1" min="0" name="monthly_collected_kg_rice" value="{user_to_edit['monthly_collected_kg_rice']}" required class="w-full px-3 py-2 border rounded-lg mb-3 text-lg">
                            <label class="block text-gray-700 font-bold mb-1">Wheat Collected This Month (kg)</label>
                            <input type="number" step="0.1" min="0" name="monthly_collected_kg_wheat" value="{user_to_edit['monthly_collected_kg_wheat']}" required class="w-full px-3 py-2 border rounded-lg mb-4 text-lg">
                            <button class="w-full bg-green-600 text-white px-4 py-3 rounded-xl font-bold hover:bg-green-700 shadow-md">Update Quota Balance</button>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>
    """
    return render_template_string(get_layout(f"Edit User {card_number}", content, 'admin'))

# --- START EXTRA FEATURE: Admin Change Password Utility ---
@app.route("/admin/change_password", methods=['GET', 'POST'])
@secondary_admin_required
def admin_change_password():
    db = get_db()
    user = g.user
    error = None
    
    PASSWORD_PATTERN = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+])[A-Za-z\d!@#$%^&*()_+]{6,8}$")

    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        
        if not bcrypt.check_password_hash(user['password_hash'], current_password):
            error = "Invalid current password."
        elif not PASSWORD_PATTERN.match(new_password):
            error = "New password must be 6-8 characters, including at least one uppercase, one lowercase, one number, and one special symbol (!@#$%^&*()_+)."
        else:
            try:
                new_password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
                db.execute('UPDATE users SET password_hash = ? WHERE card_number = ?', (new_password_hash, user['card_number']))
                db.commit()
                flash("Your password has been changed successfully. Please log in with the new password.", "success")
                session.clear()
                return redirect(url_for('admin_login'))
            except Exception as e:
                db.rollback()
                error = f"Database error during password change: {e}"
    
    if error:
        flash(error, "error")

    role = 'admin' if user['is_admin'] == 1 else 'secondary_admin'
    sidebar_html = get_admin_sidebar_html(role, user['is_admin']==1)
    
    # Client-side validation script
    password_check_script = """
    <script>
        function checkPasswordStrengthChange(password) {
            const requirements = [
                { pattern: /.{6,8}/, message: "Length 6-8 characters" },
                { pattern: /[A-Z]/, message: "One Uppercase letter" },
                { pattern: /[a-z]/, message: "One Lowercase letter" },
                { pattern: /\d/, message: "One Number" },
                { pattern: /[!@#$%^&*()_+]/, message: "One Special Symbol (!@#$%^&*()_+)" }
            ];
            const feedbackElement = document.getElementById('change-password-feedback');
            let html = '';

            requirements.forEach(req => {
                const passed = req.pattern.test(password);
                const color = passed ? 'text-green-600' : 'text-red-600';
                const icon = passed ? '✅' : '❌';
                html += `<li class="${color}">${icon} ${req.message}</li>`;
            });

            feedbackElement.innerHTML = `<ul class="list-none space-y-1">${html}</ul>`;
        }
    </script>
    """

    content = f"""
    <div class="flex flex-col md:flex-row gap-8 max-w-7xl mx-auto">
        {sidebar_html}
        <div class="flex-grow">
            <h3 class="text-3xl font-bold mb-6 text-blue-900">Change Admin Password</h3>
            <div class="bg-white p-6 rounded-xl shadow-xl max-w-md border-l-8 border-amber-600">
                <p class="text-md text-gray-600 mb-4">You are changing the password for: **{user['name']}** ({user['card_number']})</p>
                <form method="POST" onsubmit="return confirm('Are you sure you want to change your password? You will be logged out.');">
                    <label class="block text-gray-700 font-bold mb-1">Current Password</label>
                    <input type="password" name="current_password" required class="w-full px-3 py-2 border rounded-lg mb-4 text-lg">
                    
                    <label class="block text-gray-700 font-bold mb-1">New Password</label>
                    <div class="relative">
                        <input type="password" id="admin-change-password" name="new_password" required class="w-full px-3 py-2 border rounded-lg mb-2 text-lg pr-10" onkeyup="checkPasswordStrengthChange(this.value)">
                        <span class="absolute right-3 top-2 cursor-pointer emoji-fix" id="admin-change-password-toggle" onclick="togglePasswordVisibility('admin-change-password', 'admin-change-password-toggle')">👀</span>
                    </div>

                    <div id="change-password-feedback" class="bg-gray-50 p-3 rounded-lg border text-sm mb-4">
                        <p class="font-bold text-gray-700 mb-1">Password Requirements (6-8 Chars):</p>
                        <ul class="list-none space-y-1">
                            <li class="text-red-600">❌ Length 6-8 characters</li>
                            <li class="text-red-600">❌ One Uppercase letter</li>
                            <li class="text-red-600">❌ One Lowercase letter</li>
                            <li class="text-red-600">❌ One Number</li>
                            <li class="text-red-600">❌ One Special Symbol (!@#$%^&*()_+)</li>
                        </ul>
                    </div>
                    
                    <button class="w-full bg-amber-600 text-white px-4 py-3 rounded-xl font-bold hover:bg-amber-700 shadow-md">Change Password</button>
                </form>
            </div>
        </div>
    </div>
    {password_check_script}
    """
    return render_template_string(get_layout("Admin: Change Password", content, role))
# --- END EXTRA FEATURE ---


@app.route("/admin/manage_secondary_admins", methods=['GET', 'POST'])
@admin_required
def admin_manage_secondary_admins():
    db = get_db()
    
    if request.method == 'POST':
        action = request.form['action']
        card_number = request.form['card_number']
        
        if card_number == g.user['card_number']:
            flash("You cannot change the status of your own account.", "error")
        else:
            try:
                if action == 'promote':
                    db.execute('UPDATE users SET is_secondary_admin = 1, is_approved = 1, is_pre_registered = 0, policy_accepted = 1 WHERE card_number = ?', (card_number,))
                    flash(f"User **{card_number}** promoted to Secondary Admin.", "success")
                elif action == 'demote':
                    db.execute('UPDATE users SET is_secondary_admin = 0 WHERE card_number = ?', (card_number,))
                    flash(f"User **{card_number}** demoted to Regular User.", "success")
                db.commit()
            except sqlite3.Error as e:
                db.rollback()
                flash(f"Database Error: {e}", "error")

    users = db.execute("SELECT * FROM users WHERE is_admin = 0 ORDER BY is_secondary_admin DESC, name").fetchall()
    
    users_html = ""
    for user in users:
        status = "Secondary Admin 👑" if user['is_secondary_admin'] == 1 else "Regular User"
        status_color = "text-yellow-700" if user['is_secondary_admin'] == 1 else "text-blue-600"
        
        if user['is_secondary_admin'] == 0:
            action_button = f"""
            <form method="POST" class="inline-block" onsubmit="return confirm('Promote {user['card_number']} to Secondary Admin?');">
                <input type="hidden" name="action" value="promote">
                <input type="hidden" name="card_number" value="{user['card_number']}">
                <button type="submit" class="bg-green-600 hover:bg-green-700 text-white font-bold py-2 px-4 rounded-xl text-sm shadow-md">Promote to Admin</button>
            </form>
            """
        else:
            action_button = f"""
            <form method="POST" class="inline-block" onsubmit="return confirm('Demote {user['card_number']} to Regular User?');">
                <input type="hidden" name="action" value="demote">
                <input type="hidden" name="card_number" value="{user['card_number']}">
                <button type="submit" class="bg-red-600 hover:bg-red-700 text-white font-bold py-2 px-4 rounded-xl text-sm shadow-md">Demote</button>
            </form>
            """

        users_html += f"""
        <div class="bg-white p-5 rounded-xl shadow-lg mb-4 border-l-8 border-{'yellow' if user['is_secondary_admin'] == 1 else 'blue'}-600">
            <div class="flex justify-between items-center">
                <div>
                    <p class="font-extrabold text-xl">{user['name']} ({user['card_number']})</p>
                    <p class="text-md font-bold {status_color} mt-1">Status: {status}</p>
                </div>
                <div>{action_button}</div>
            </div>
        </div>
        """

    role = 'admin' if g.user['is_admin'] == 1 else 'secondary_admin'
    sidebar_html = get_admin_sidebar_html(role, g.user['is_admin']==1)
    
    content = f"""
    <div class="flex flex-col md:flex-row gap-8 max-w-7xl mx-auto">
        {sidebar_html}
        <div class="flex-grow">
            <h2 class="text-3xl font-bold mb-6 text-blue-900">Manage Secondary Admins (Delegated Access)</h2>
            <p class="text-lg text-gray-600 mb-6">Secondary Admins have access to most admin functions (users, stock, slots, validation, reports) but cannot modify global system config or manage other admins.</p>
            {users_html if users_html else "<p class='text-xl font-bold text-gray-600 p-6 bg-gray-100 rounded-xl border border-gray-300'>No users available to promote/demote.</p>"}
        </div>
    </div>
    """
    return render_template_string(get_layout("Admin: Manage Admins", content, 'admin'))


@app.route("/admin/manage_items", methods=['GET', 'POST'])
@secondary_admin_required
def admin_manage_items():
    db = get_db()
    is_main_admin = g.user['is_admin'] == 1

    if request.method == 'POST':
        action = request.form['action']
        
        try:
            db.execute('BEGIN TRANSACTION')
            
            if action == 'add_item':
                if not is_main_admin: raise Exception("Permission denied. Only Main Admin can add items.")
                name = request.form['name'].strip()
                unit = request.form['unit'].strip()
                stock = float(request.form['stock'])
                unit_price = float(request.form['unit_price'])
                free_limit_kg = float(request.form['free_limit_kg'])
                
                if stock < 0 or unit_price < 0 or free_limit_kg < 0:
                    raise ValueError("Values cannot be negative.")
                if not name or not unit:
                    raise ValueError("Item Name and Unit are required.")
                    
                db.execute("""
                    INSERT INTO items (name, stock, unit_price, free_limit_kg, unit)
                    VALUES (?, ?, ?, ?, ?)
                """, (name, stock, unit_price, free_limit_kg, unit))
                message = f"Item **{name}** added successfully."
            
            elif action == 'update_stock':
                item_id = request.form['item_id']
                new_stock = float(request.form['new_stock'])
                if new_stock < 0: raise ValueError("Stock cannot be negative.")
                db.execute('UPDATE items SET stock = ? WHERE id = ?', (new_stock, item_id))
                message = "Stock updated successfully."
                
            elif action == 'update_details':
                if not is_main_admin: raise Exception("Permission denied. Only Main Admin can update item details.")
                item_id = request.form['item_id']
                unit_price = float(request.form['unit_price'])
                free_limit_kg = float(request.form['free_limit_kg'])
                if unit_price < 0 or free_limit_kg < 0: raise ValueError("Values cannot be negative.")
                db.execute('UPDATE items SET unit_price = ?, free_limit_kg = ? WHERE id = ?', (unit_price, free_limit_kg, item_id))
                message = "Item details (Price/Limit) updated successfully."
                
            elif action == 'delete_item':
                if not is_main_admin: raise Exception("Permission denied. Only Main Admin can delete items.")
                item_id = request.form['item_id']
                db.execute('DELETE FROM items WHERE id = ?', (item_id,))
                message = "Item deleted successfully."
            
            else:
                raise Exception("Invalid action.")
            
            db.commit()
            flash(message, "success")
            
        except ValueError as e:
            db.rollback()
            flash(f"Input Error: {e}", "error")
        except sqlite3.IntegrityError:
            db.rollback()
            flash("An item with that name already exists.", "error")
        except Exception as e:
            db.rollback()
            flash(f"Operation failed: {e}", "error")
            
        return redirect(url_for('admin_manage_items'))

    items = db.execute("SELECT * FROM items ORDER BY name").fetchall()
    
    items_html = ""
    for item in items:
        stock_form = f"""
        <form method="POST" class="flex gap-3 items-center mt-3">
            <input type="hidden" name="action" value="update_stock">
            <input type="hidden" name="item_id" value="{item['id']}">
            <label class="text-sm font-semibold text-gray-700">Stock (In {item['unit']}):</label>
            <input type="number" step="0.1" min="0" name="new_stock" value="{item['stock']:.1f}" class="w-24 px-3 py-2 border rounded-lg text-lg font-semibold text-center">
            <button class="bg-yellow-500 hover:bg-yellow-600 text-gray-800 px-4 py-2 rounded-xl text-sm font-bold shadow-md">Update</button>
        </form>
        """
        
        details_form = ""
        if is_main_admin:
            details_form = f"""
            <div class="mt-4 border-t pt-4">
                <h5 class="text-sm font-bold mb-2 text-blue-700">Details & Price (Admin Only)</h5>
                <form method="POST" class="grid grid-cols-2 gap-3">
                    <input type="hidden" name="action" value="update_details">
                    <input type="hidden" name="item_id" value="{item['id']}">
                    <div class="col-span-1">
                        <label class="text-xs">Price (₹/{item['unit']})</label>
                        <input type="number" step="0.01" min="0" name="unit_price" value="{item['unit_price']:.2f}" class="w-full px-2 py-1 border rounded-lg text-md">
                    </div>
                    <div class="col-span-1">
                        <label class="text-xs">Free Limit ({item['unit']})</label>
                        <input type="number" step="0.1" min="0" name="free_limit_kg" value="{item['free_limit_kg']:.1f}" class="w-full px-2 py-1 border rounded-lg text-md">
                    </div>
                    <div class="col-span-2 flex justify-between mt-3">
                        <button class="bg-blue-600 text-white px-4 py-2 rounded-xl text-sm font-bold shadow-md">Update Details</button>
                        <button class="bg-red-600 text-white px-4 py-2 rounded-xl text-sm font-bold shadow-md" form="delete_form_{item['id']}" onclick="return confirm('WARNING: Permanently delete {item['name']}? This cannot be undone.');">Delete Item</button>
                    </div>
                </form>
                <form id="delete_form_{item['id']}" method="POST" class="hidden">
                    <input type="hidden" name="action" value="delete_item">
                    <input type="hidden" name="item_id" value="{item['id']}">
                </form>
            </div>
            """
        
        items_html += f"""
        <div class="bg-white p-6 rounded-xl shadow-xl border-l-8 border-yellow-600">
            <h4 class="text-2xl font-extrabold text-yellow-800 flex items-center gap-2"><span class="emoji-fix">🍚</span> {item['name']} <span class="text-sm text-gray-500 font-medium">({item['unit']})</span></h4>
            <p class="text-md text-gray-600">Unit Price: **₹{item['unit_price']:.2f}** | Free Limit: **{item['free_limit_kg']:.1f} {item['unit']}**</p>
            <div>
                {stock_form}
                {details_form}
            </div>
        </div>
        """

    sidebar_html = get_admin_sidebar_html(g.user['card_number'], is_main_admin)
    
    add_item_form = ""
    if is_main_admin:
        add_item_form = f"""
        <div class="bg-white p-8 rounded-2xl shadow-2xl mb-8 border-t-8 border-green-600">
            <h3 class="text-2xl font-bold mb-4 text-green-800 flex items-center gap-2"><span class="emoji-fix">➕</span> Add New Ration Item</h3>
            <p class="text-sm text-gray-600 mb-4">Note: If you add Rice/Wheat, update the System Config quotas accordingly.</p>
            <form method="POST">
                <input type="hidden" name="action" value="add_item">
                <div class="grid grid-cols-2 gap-4">
                    <input type="text" name="name" placeholder="Item Name (e.g., Sugar)" required class="w-full px-3 py-2 border rounded-lg text-lg">
                    <input type="text" name="unit" placeholder="Unit (e.g., kg, Litre, pc)" required class="w-full px-3 py-2 border rounded-lg text-lg">
                    <input type="number" step="0.1" name="stock" placeholder="Initial Stock" required class="w-full px-3 py-2 border rounded-lg text-lg">
                    <input type="number" step="0.01" name="unit_price" placeholder="Unit Price (₹)" required class="w-full px-3 py-2 border rounded-lg text-lg">
                    <div class="col-span-2">
                        <input type="number" step="0.1" name="free_limit_kg" placeholder="Free Limit (kg/L/pc, default 0)" value="0" class="w-full px-3 py-2 border rounded-lg text-lg">
                        <p class="text-xs text-gray-500 mt-1">This sets the maximum free quota per user, per month.</p>
                    </div>
                </div>
                <button type="submit" class="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-4 px-4 rounded-xl mt-6 shadow-lg text-xl">Add Item to Inventory</button>
            </form>
        </div>
        """

    content = f"""
    <div class="flex flex-col md:flex-row gap-8 max-w-7xl mx-auto">
        {sidebar_html}
        <div class="flex-grow">
            <h3 class="text-3xl font-bold mb-6 text-blue-900">Manage Inventory & Item Details</h3>
            
            {add_item_form}
            
            <h3 class="text-2xl font-extrabold mb-4 text-yellow-800">Existing Inventory Stock</h3>
            <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {items_html if items_html else "<p class='text-xl font-bold text-gray-600 p-6 bg-gray-100 rounded-xl border border-gray-300'>No items found in the inventory.</p>"}
            </div>
        </div>
    </div>
    """
    return render_template_string(get_layout("Admin: Manage Items", content, 'admin' if is_main_admin else 'secondary_admin'))


@app.route("/admin/manage_slots", methods=['GET', 'POST'])
@secondary_admin_required
def admin_manage_slots():
    db = get_db()

    if request.method == 'POST':
        action = request.form['action']
        
        try:
            db.execute('BEGIN TRANSACTION')
            
            if action == 'add':
                date_str = request.form['date']
                time_str = request.form['time']
                capacity = int(request.form['capacity'])
                
                date_time_obj = datetime.datetime.strptime(f"{date_str} {time_str}", '%Y-%m-%d %H:%M')
                if date_time_obj < datetime.datetime.now():
                    raise ValueError("Cannot create slot in the past.")
                if capacity <= 0:
                    raise ValueError("Capacity must be positive.")
                    
                db.execute("INSERT INTO slots (date_time, capacity) VALUES (?, ?)", (date_time_obj.strftime('%Y-%m-%d %H:%M:%S'), capacity))
                message = "New slot added successfully."
                
            elif action == 'update':
                slot_id = request.form['slot_id']
                new_capacity = int(request.form['new_capacity'])
                slot = db.execute("SELECT * FROM slots WHERE id = ?", (slot_id,)).fetchone()
                
                if new_capacity < slot['booked_count']:
                    raise ValueError(f"New capacity ({new_capacity}) cannot be less than currently booked slots ({slot['booked_count']}).")
                if new_capacity <= 0:
                    raise ValueError("Capacity must be positive.")
                
                db.execute('UPDATE slots SET capacity = ? WHERE id = ?', (new_capacity, slot_id))
                message = "Slot capacity updated."
                
            elif action == 'delete':
                slot_id = request.form['slot_id']
                slot = db.execute("SELECT * FROM slots WHERE id = ?", (slot_id,)).fetchone()
                if slot['booked_count'] > 0:
                    raise Exception(f"Cannot delete slot with {slot['booked_count']} existing bookings. Consider reducing capacity to match booked count if no new bookings are desired.")
                
                db.execute('DELETE FROM slots WHERE id = ?', (slot_id,))
                message = "Slot deleted successfully."
            
            else:
                raise Exception("Invalid action.")

            db.commit()
            flash(message, "success")
            
        except ValueError as e:
            db.rollback()
            flash(f"Input Error: {e}", "error")
        except sqlite3.IntegrityError:
            db.rollback()
            flash("A slot already exists at that exact date and time.", "error")
        except Exception as e:
            db.rollback()
            flash(f"Operation failed: {e}", "error")
            
        return redirect(url_for('admin_manage_slots'))

    slots = db.execute("SELECT * FROM slots WHERE date_time > ? ORDER BY date_time", (datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),)).fetchall()
    
    slots_html = ""
    for s in slots:
        dt = datetime.datetime.strptime(s['date_time'], '%Y-%m-%d %H:%M:%S')
        slots_html += f"""
        <div class="bg-white p-5 rounded-xl shadow-lg mb-4 border-l-8 border-{'green' if s['booked_count'] < s['capacity'] else 'red'}-600">
            <p class="font-extrabold text-xl text-blue-800">{dt.strftime('%A, %d %b %Y')}</p>
            <p class="font-extrabold text-2xl text-red-700">{dt.strftime('%I:%M %p')}</p>
            <p class="text-md text-gray-600">Booked: **{s['booked_count']}** / Capacity: **{s['capacity']}**</p>
            
            <form method="POST" class="flex gap-3 items-center mt-3">
                <input type="hidden" name="action" value="update">
                <input type="hidden" name="slot_id" value="{s['id']}">
                <label class="text-sm font-semibold text-gray-700">New Cap:</label>
                <input type="number" min="{s['booked_count']}" name="new_capacity" value="{s['capacity']}" class="w-16 px-3 py-2 border rounded-lg text-lg text-center">
                <button class="bg-blue-600 text-white px-4 py-2 rounded-xl font-bold hover:bg-blue-700 shadow-md">Update</button>
            </form>
            <form method="POST" onsubmit="return confirm('WARNING: Delete this slot? This is FORBIDDEN if bookings exist.');" class="inline-block mt-3">
                <input type="hidden" name="action" value="delete">
                <input type="hidden" name="slot_id" value="{s['id']}">
                <button class="bg-red-600 text-white px-4 py-2 rounded-xl font-bold hover:bg-red-700 shadow-md" {'disabled' if s['booked_count'] > 0 else ''}>Delete</button>
            </form>
        </div>
        """

    role = 'admin' if g.user['is_admin'] == 1 else 'secondary_admin'
    sidebar_html = get_admin_sidebar_html(role, g.user['is_admin']==1)

    content = f"""
    <div class="flex flex-col md:flex-row gap-8 max-w-7xl mx-auto">
        {sidebar_html}
        <div class="flex-grow">
            <h2 class="text-3xl font-bold mb-6 text-blue-900">Manage Collection Slots (Queue Management)</h2>
            <p class="text-lg text-gray-600 mb-6">Create new slots and adjust capacity. Deletion is blocked if bookings are present.</p>
            
            <div class="bg-white p-6 rounded-xl shadow-xl mb-8 border-t-8 border-green-600">
                <h3 class="text-2xl font-semibold mb-4 text-green-800 flex items-center gap-2"><span class="emoji-fix">➕</span> Add New Slot</h3>
                <form method="POST" class="grid grid-cols-4 gap-4 items-end">
                    <input type="hidden" name="action" value="add">
                    <div class="col-span-1">
                        <label class="text-sm font-semibold">Date</label>
                        <input name="date" type="date" class="border p-2 rounded-lg w-full text-lg" value="{(datetime.date.today() + datetime.timedelta(days=1)).isoformat()}" required>
                    </div>
                    <div class="col-span-1">
                        <label class="text-sm font-semibold">Time (HH:MM 24h)</label>
                        <input name="time" type="time" class="border p-2 rounded-lg w-full text-lg" value="10:00" required>
                    </div>
                    <div class="col-span-1">
                        <label class="text-sm font-semibold">Capacity</label>
                        <input type="number" name="capacity" class="border p-2 rounded-lg w-full text-lg" value="10" required>
                    </div>
                    <div class="col-span-1">
                        <button class="w-full bg-green-600 text-white px-4 py-3 rounded-xl font-bold hover:bg-green-700 shadow-md">Add Slot</button>
                    </div>
                </form>
            </div>
            
            <h3 class="text-2xl font-extrabold mb-4 text-blue-800">Existing Future Slots</h3>
            <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
                {slots_html if slots_html else "<p class='text-xl font-bold text-gray-600 p-6 bg-gray-100 rounded-xl border border-gray-300'>No future slots scheduled or all are full.</p>"}
            </div>
        </div>
    </div>
    """
    return render_template_string(get_layout("Admin: Manage Slots", content, 'admin'))

@app.route("/admin/system_config", methods=['GET', 'POST'])
@admin_required
def admin_system_config():
    db = get_db()
    
    if request.method == 'POST':
        action = request.form['action']
        
        try:
            db.execute('BEGIN TRANSACTION')
            if action == 'update_config':
                freeze_status = request.form.get('system_freeze', '0')
                max_rice = float(request.form['max_free_rice_kg'])
                max_wheat = float(request.form['max_free_wheat_kg'])
                max_household = int(request.form['max_household_size'])
                
                if max_rice < 0 or max_wheat < 0 or max_household < 1:
                    raise ValueError("Quota limits and household size must be positive numbers.")
                    
                set_config('system_freeze', freeze_status)
                set_config('max_free_rice_kg', max_rice)
                set_config('max_free_wheat_kg', max_wheat)
                set_config('max_household_size', max_household)
                
                flash("System configuration updated.", "success")

            elif action == 'monthly_roll_over':
                db.execute("""
                    UPDATE users
                    SET monthly_collected_kg_rice = 0.0,
                        monthly_collected_kg_wheat = 0.0
                    WHERE is_admin = 0 AND is_secondary_admin = 0
                """)
                set_config('last_reset_date', datetime.date.today().strftime('%Y-%m'))
                flash(f"Monthly Roll-over complete! All user quotas reset for {datetime.date.today().strftime('%Y-%m')}.", "success")
            
            else:
                raise Exception("Invalid action.")
            
            db.commit()
            
        except ValueError as e:
            db.rollback()
            flash(f"Input Error: {e}", "error")
        except Exception as e:
            db.rollback()
            flash(f"Unexpected error: {e}", "error")

    config_map = {
        'system_freeze': get_config('system_freeze', '0'),
        'max_free_rice_kg': get_config('max_free_rice_kg', '30'),
        'max_free_wheat_kg': get_config('max_free_wheat_kg', '25'),
        'max_household_size': get_config('max_household_size', '10'),
        'last_reset_date': get_config('last_reset_date', 'N/A'),
    }

    sidebar_html = get_admin_sidebar_html(g.user['card_number'], g.user['is_admin']==1)

    content = f"""
    <div class="flex flex-col md:flex-row gap-8 max-w-7xl mx-auto">
        {sidebar_html}
        <div class="flex-grow">
            <h3 class="text-3xl font-bold mb-6 text-blue-900">System Configuration & Policy Management</h3>
            <p class="text-lg text-gray-600 mb-6">Use caution! These settings affect the entire beneficiary system.</p>
            
            <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                
                <div class="bg-white p-6 rounded-xl shadow-xl border-l-8 border-blue-600">
                    <h4 class="text-xl font-extrabold mb-4 text-blue-800">Global Quota & System Status</h4>
                    <form method="POST">
                        <input type="hidden" name="action" value="update_config">
                        
                        <label class="block text-gray-700 font-bold mb-1">Max Free Rice Quota (kg)</label>
                        <input type="number" step="1" min="0" name="max_free_rice_kg" value="{config_map['max_free_rice_kg']}" required class="w-full px-3 py-2 border rounded-lg mb-3 text-lg">
                        
                        <label class="block text-gray-700 font-bold mb-1">Max Free Wheat Quota (kg)</label>
                        <input type="number" step="1" min="0" name="max_free_wheat_kg" value="{config_map['max_free_wheat_kg']}" required class="w-full px-3 py-2 border rounded-lg mb-3 text-lg">
                        
                        <label class="block text-gray-700 font-bold mb-1">Max Household Size</label>
                        <input type="number" step="1" min="1" name="max_household_size" value="{config_map['max_household_size']}" required class="w-full px-3 py-2 border rounded-lg mb-3 text-lg">
                        
                        <label class="block text-gray-700 font-bold mb-1">System Freeze Status</label>
                        <select name="system_freeze" class="w-full px-3 py-2 border rounded-lg mb-4 text-lg">
                            <option value="0" {'selected' if config_map['system_freeze'] == '0' else ''}>0 - Active (Allow Bookings)</option>
                            <option value="1" {'selected' if config_map['system_freeze'] == '1' else ''}>1 - Frozen (Block New Bookings)</option>
                        </select>
                        
                        <button class="w-full bg-blue-600 text-white px-4 py-3 rounded-xl font-bold hover:bg-blue-700 shadow-md">Update Global Settings</button>
                    </form>
                </div>
                
                <div class="space-y-6">
                    <div class="bg-white p-6 rounded-xl shadow-xl border-l-8 border-yellow-600">
                        <h4 class="text-xl font-extrabold mb-4 text-yellow-800">Manual Quota Reset</h4>
                        <p class="text-md text-gray-600 mb-4">The system resets quotas on the 1st of every month automatically. Use this for emergency roll-overs.</p>
                        <form method="POST" onsubmit="return confirm('ADMIN WARNING: Are you sure you want to manually reset ALL user quotas to zero?');">
                            <input type="hidden" name="action" value="monthly_roll_over">
                            <p class="mb-3 font-semibold">Last Reset Recorded: <span class="text-red-600">{config_map['last_reset_date']}</span></p>
                            <button class="w-full bg-yellow-600 text-white px-4 py-3 rounded-xl font-bold hover:bg-yellow-700 shadow-md">Force Monthly Quota Reset</button>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>
    """
    return render_template_string(get_layout("Admin: System Config", content, 'admin'))

@app.route("/admin/reports")
@secondary_admin_required
def admin_reports():
    db = get_db()
    
    total_revenue = db.execute("SELECT SUM(total_cost) FROM orders WHERE is_paid = 1").fetchone()[0] or 0.0
    
    total_items_sold = db.execute("""
        SELECT item_name, SUM(quantity) as total_qty
        FROM orders WHERE is_paid = 1
        GROUP BY item_name
        ORDER BY total_qty DESC
    """).fetchall()
    
    slot_stats = db.execute("SELECT SUM(capacity) as total_capacity, SUM(booked_count) as total_booked FROM slots").fetchone()
    total_capacity = slot_stats['total_capacity'] or 0
    total_booked = slot_stats['total_booked'] or 0
    overall_utilization_rate = (total_booked / total_capacity * 100) if total_capacity > 0 else 0
    
    total_orders = db.execute("SELECT COUNT(DISTINCT token) FROM orders").fetchone()[0] or 0
    collected_orders = db.execute("SELECT COUNT(DISTINCT token) FROM orders WHERE is_paid = 1").fetchone()[0] or 0
    pending_orders = total_orders - collected_orders
    
    item_distribution_html = "<ul class='list-none space-y-2'>"
    for item in total_items_sold:
        unit_row = db.execute('SELECT unit FROM items WHERE name = ?', (item['item_name'],)).fetchone()
        unit = unit_row['unit'] if unit_row else 'units'
        item_distribution_html += f"""
        <li class="flex justify-between border-b pb-1 text-lg font-semibold">
            <span class="text-gray-700">**{item['item_name']}**</span>
            <span class="text-blue-600">{item['total_qty']:.1f} {unit}</span>
        </li>
        """
    item_distribution_html += "</ul>"
    
    role = 'admin' if g.user['is_admin'] == 1 else 'secondary_admin'
    sidebar_html = get_admin_sidebar_html(role, g.user['is_admin']==1)
    
    content = f"""
    <div class="flex flex-col md:flex-row gap-8 max-w-7xl mx-auto">
        {sidebar_html}
        <div class="flex-grow">
            <h3 class="text-3xl font-bold mb-6 text-blue-900">System Performance Reports</h3>
            
            <div class="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
                <div class="bg-white p-6 rounded-xl shadow-xl border-l-8 border-green-600">
                    <h4 class="text-xl font-extrabold mb-3 text-green-800 flex items-center gap-2"><span class="emoji-fix">💰</span> Total Revenue (COD Paid)</h4>
                    <p class="text-5xl font-extrabold text-green-700">₹{total_revenue:,.2f}</p>
                    <p class="text-sm text-gray-500 mt-2">Total amount collected from non-free items.</p>
                </div>
                <div class="bg-white p-6 rounded-xl shadow-xl border-l-8 border-blue-600">
                    <h4 class="text-xl font-extrabold mb-3 text-blue-800 flex items-center gap-2"><span class="emoji-fix">📊</span> Overall Slot Utilization</h4>
                    <p class="text-5xl font-extrabold text-blue-700">{overall_utilization_rate:.1f}%</p>
                    <p class="text-sm text-gray-500 mt-2">({total_booked} slots booked out of {total_capacity} total capacity so far.)</p>
                </div>
            </div>
            
            <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
                {get_stat_card("Total Bookings (Tokens)", total_orders, icon="📋", color="gray")}
                {get_stat_card("Tokens Collected (Paid)", collected_orders, icon="✅", color="green")}
                {get_stat_card("Tokens Pending Collection", pending_orders, icon="🔴", color="red")}
            </div>
            
            <div class="bg-white p-6 rounded-xl shadow-xl border-l-8 border-yellow-600">
                <h4 class="text-xl font-extrabold mb-4 text-yellow-800 flex items-center gap-2"><span class="emoji-fix">📦</span> Item Distribution Summary (Collected)</h4>
                {item_distribution_html if total_items_sold else "<p class='text-lg text-gray-600'>No collection data found to generate item distribution report.</p>"}
            </div>
        </div>
    </div>
    """
    return render_template_string(get_layout("Admin: Reports", content, role))


@app.route("/uploads/<path:filename>")
def uploads(filename):
    try:
        if ".." in filename or filename.startswith('/'):
            return "", 404
        return send_from_directory(UPLOAD_DIR, filename)
    except FileNotFoundError:
        return "", 404

# ============================================================
# RUN APP
# ============================================================

if __name__ == '__main__':
    # REMEMBER: If you delete 'ration.db' and run this code, it will recreate the database
    # with the unfrozen setting ('system_freeze': '0') and default admin/user accounts.
    app.run(debug=True, host='0.0.0.0', port=5000)
