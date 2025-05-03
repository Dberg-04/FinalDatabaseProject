from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from functools import wraps

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Change this in production!

# Database initialization
def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'user'
    )
    ''')
    
    # Create tasks table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS tasks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT,
        user_id INTEGER NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')
    
    # Add some test users if they don't exist
    try:
        cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
                      ('admin', generate_password_hash('admin123'), 'admin'))
        cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
                      ('user1', generate_password_hash('password1'), 'user'))
        cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
                      ('user2', generate_password_hash('password2'), 'user'))
        conn.commit()
    except sqlite3.IntegrityError:
        pass  # Users already exist
    
    conn.close()

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Admin required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'danger')
            return redirect(url_for('login'))
        
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute('SELECT role FROM users WHERE id = ?', (session['user_id'],))
        user_role = cursor.fetchone()[0]
        conn.close()
        
        if user_role != 'admin':
            flash('You need admin privileges to access this page.', 'danger')
            return redirect(url_for('dashboard'))
            
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute('SELECT id, username, password, role FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()
        
        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['role'] = user[3]
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'danger')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('register'))
        
        hashed_password = generate_password_hash(password)
        
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        try:
            cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', 
                         (username, hashed_password))
            conn.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists.', 'danger')
        finally:
            conn.close()
    
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/tasks')
@login_required
def tasks():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    if session['role'] == 'admin':
        cursor.execute('SELECT tasks.id, title, description, username FROM tasks JOIN users ON tasks.user_id = users.id')
    else:
        cursor.execute('SELECT id, title, description FROM tasks WHERE user_id = ?', (session['user_id'],))
    
    tasks = cursor.fetchall()
    conn.close()
    
    return render_template('tasks.html', tasks=tasks)

@app.route('/add_task', methods=['POST'])
@login_required
def add_task():
    title = request.form['title']
    description = request.form['description']
    
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('INSERT INTO tasks (title, description, user_id) VALUES (?, ?, ?)',
                  (title, description, session['user_id']))
    conn.commit()
    conn.close()
    
    flash('Task added successfully!', 'success')
    return redirect(url_for('tasks'))

@app.route('/delete_task/<int:task_id>')
@login_required
def delete_task(task_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    if session['role'] == 'admin':
        cursor.execute('DELETE FROM tasks WHERE id = ?', (task_id,))
    else:
        cursor.execute('DELETE FROM tasks WHERE id = ? AND user_id = ?', 
                      (task_id, session['user_id']))
    
    conn.commit()
    conn.close()
    
    flash('Task deleted successfully!', 'success')
    return redirect(url_for('tasks'))

@app.route('/users')
@admin_required
def users():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, role FROM users')
    users = cursor.fetchall()
    conn.close()
    
    return render_template('users.html', users=users)

@app.route('/promote_user/<int:user_id>')
@admin_required
def promote_user(user_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET role = "admin" WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    
    flash('User promoted to admin!', 'success')
    return redirect(url_for('users'))

@app.route('/delete_user/<int:user_id>')
@admin_required
def delete_user(user_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # First delete user's tasks
    cursor.execute('DELETE FROM tasks WHERE user_id = ?', (user_id,))
    # Then delete the user
    cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
    
    conn.commit()
    conn.close()
    
    flash('User deleted successfully!', 'success')
    return redirect(url_for('users'))

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
