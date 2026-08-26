import os
import sqlite3
import pandas as pd
from datetime import datetime
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET_KEY"]

# --- CONFIGURATION ---
DB_PATH = "data/biasguard.db"

# --- DATABASE SETUP ---
def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    if not os.path.exists("data"): os.makedirs("data")
    conn = get_db_connection()
    # Users (Local DB as Cache, uid for Firebase)
    conn.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        uid TEXT UNIQUE
    )''')
    # Audit History Table
    conn.execute('''CREATE TABLE IF NOT EXISTS history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        timestamp TEXT NOT NULL,
        filename TEXT NOT NULL,
        ratio REAL NOT NULL,
        severity TEXT NOT NULL,
        male_rate REAL,
        female_rate REAL,
        ai_insight TEXT,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    # Partnerships Table
    conn.execute('''CREATE TABLE IF NOT EXISTS partnerships (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        email TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    conn.commit()
    conn.close()

init_db()

# --- AUTH DECORATOR ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

# --- CORE FAIRNESS ENGINE ---
def generate_impactful_insight(male_rate, female_rate, ratio, severity):
    gap = round(abs(male_rate - female_rate) * 100, 1)
    problem = f"The model exhibits a <b class='text-white'>{severity}</b> equity variance. A {gap}% gap indicates systematic favoritism in the decision vectors."
    impact = "Significant barriers detected in hiring and lending access for protected segments." if severity == "CRITICAL" else "Subtle bias markers are beginning to emerge."
    return f"{problem}\n\nIMPACT: {impact}"

def calculate_metrics(df):
    try:
        df.columns = df.columns.str.strip().str.lower()
        target = 'approval' if 'approval' in df.columns else 'approved'
        if 'gender' in df.columns: df['gender'] = df['gender'].astype(str).str.strip().str.lower()
        
        male_df = df[df['gender'].isin(['male', 'm'])]
        female_df = df[df['gender'].isin(['female', 'f'])]
        
        m_rate = male_df[target].mean() if len(male_df) > 0 else 0
        f_rate = female_df[target].mean() if len(female_df) > 0 else 0
        ratio = f_rate / m_rate if m_rate > 0 else 1.0
        severity = "CRITICAL" if ratio < 0.8 else "WARNING" if ratio < 0.9 else "SAFE"
        
        return {
            "male_rate": float(m_rate), "female_rate": float(f_rate),
            "ratio": float(ratio), "severity": severity,
            "ai_insight": generate_impactful_insight(m_rate, f_rate, ratio, severity),
            "counts": {"approved": int(df[target].sum()), "rejected": int(len(df) - df[target].sum())}
        }
    except: return None

# --- AUTH ROUTES ---
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        name, email, password = request.form.get("name"), request.form.get("email"), request.form.get("password")
        conn = get_db_connection()
        try:
            conn.execute("INSERT INTO users (name, email, password) VALUES (?, ?, ?)", 
                         (name, email, generate_password_hash(password)))
            conn.commit()
            flash("Signup successful! Please login.")
            return redirect(url_for("login"))
        except:
            flash("Email already exists or invalid data.")
        finally: conn.close()
    return render_template("auth.html", mode="signup")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email, password = request.form.get("email"), request.form.get("password")
        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        conn.close()
        if user and check_password_hash(user["password"], password):
            session["user_id"] = user["id"]
            session["user_name"] = user["name"]
            return redirect(url_for("index"))
        flash("Invalid credentials! Please try again.")
    return render_template("auth.html", mode="login")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

@app.route("/partner", methods=["POST"])
@login_required
def partner_request():
    conn = get_db_connection()
    user = conn.execute("SELECT name, email FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    if user:
        conn.execute("INSERT INTO partnerships (user_id, name, email, timestamp) VALUES (?, ?, ?, ?)",
                     (session["user_id"], user["name"], user["email"], datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()
    conn.close()
    return jsonify({"success": True})

# --- APP ROUTES ---
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        if "user_id" not in session: return jsonify({"error": "Login required to audit"}), 401
        file = request.files.get("file")
        if not file: return jsonify({"error": "No file"}), 400

        try:
            metrics = calculate_metrics(pd.read_csv(file))
            if not metrics: return jsonify({"error": "Invalid Data"}), 400
            
            conn = get_db_connection()
            conn.execute('''INSERT INTO history 
                (user_id, timestamp, filename, ratio, severity, male_rate, female_rate, ai_insight) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)''', 
                (session["user_id"], datetime.now().strftime("%Y-%m-%d %H:%M:%S"), file.filename, 
                 metrics["ratio"], metrics["severity"], metrics["male_rate"], metrics["female_rate"], metrics["ai_insight"]))
            conn.commit()
            
            # Fetch recent history for trend
            history = conn.execute("SELECT ratio, timestamp FROM history WHERE user_id = ? ORDER BY id DESC LIMIT 10", 
                                   (session["user_id"],)).fetchall()
            conn.close()
            
            return jsonify({**metrics, "history": [dict(h) for h in history]})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    return render_template("index.html")

@app.route("/history")
@login_required
def history_dashboard():
    conn = get_db_connection()
    # Explicit conversion to dictionary for JSON serialization in template
    history_rows = conn.execute("SELECT * FROM history WHERE user_id = ? ORDER BY id DESC", (session["user_id"],)).fetchall()
    history = [dict(row) for row in history_rows]
    
    total = len(history)
    avg_bias = sum(h["ratio"] for h in history) / total if total > 0 else 0
    stats = {
        "total": total, 
        "avg_bias": round(avg_bias, 2), 
        "critical_count": len([h for h in history if h["severity"] == "CRITICAL"]),
        "user_name": session.get("user_name")
    }
    conn.close()
    return render_template("history.html", history=history, stats=stats)

@app.route("/delete_history/<int:audit_id>", methods=["POST"])
@login_required
def delete_history(audit_id):
    conn = get_db_connection()
    conn.execute("DELETE FROM history WHERE id = ? AND user_id = ?", (audit_id, session["user_id"]))
    conn.commit()
    conn.close()
    return jsonify({"success": True})

if __name__ == "__main__":
    app.run(debug=True, port=5001)