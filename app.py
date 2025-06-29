from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, g
from flask_mail import Mail, Message
from dotenv import load_dotenv
from flask_wtf import CSRFProtect
import os
import sqlite3
from functools import wraps
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import time
import sys  # Moved import here

load_dotenv()  # Load environment variables from .env file

app = Flask(__name__)
# Use a secure secret key from environment variable
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(32))

# CSRF Protection
csrf = CSRFProtect(app)

# Email configuration (Gmail SMTP setup)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')

# Initialize Flask-Mail
mail = Mail(app)

DATABASE = os.path.join(app.root_path, 'site.db')
UPLOAD_FOLDER = os.path.join('static', 'images', 'gallery')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# --- Reviews Database Setup ---
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            review TEXT NOT NULL,
            created TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    # --- Ensure 'approved' column exists in reviews ---
    try:
        columns = [row[1] for row in conn.execute("PRAGMA table_info(reviews)")]
        if 'approved' not in columns:
            conn.execute('ALTER TABLE reviews ADD COLUMN approved INTEGER DEFAULT 0')
            conn.commit()
    except Exception as e:
        print(f"Error ensuring 'approved' column in reviews: {e}", file=sys.stderr)
        raise
    # Add reset_token and reset_token_expiry to admin if not exists
    conn2 = sqlite3.connect(DATABASE)
    try:
        conn2.execute('ALTER TABLE admin ADD COLUMN reset_token TEXT')
    except Exception:
        pass
    try:
        conn2.execute('ALTER TABLE admin ADD COLUMN reset_token_expiry INTEGER')
    except Exception:
        pass
    conn.close()
    conn2.close()

init_db()

def debug_print_review_columns():
    conn = get_db()
    columns = [row[1] for row in conn.execute("PRAGMA table_info(reviews)")]
    print("Reviews table columns:", columns)
    conn.close()

debug_print_review_columns()
# --- End Reviews Database Setup ---

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

# Store failed attempts in memory (for production, use a persistent store)
FAILED_LOGINS = {}

def is_locked_out(ip):
    info = FAILED_LOGINS.get(ip)
    if not info:
        return False
    attempts, last_attempt = info
    if attempts >= 5 and (datetime.now() - last_attempt) < timedelta(minutes=10):
        return True
    if (datetime.now() - last_attempt) > timedelta(minutes=10):
        FAILED_LOGINS.pop(ip)
    return False

@app.before_request
def enforce_https_in_production():
    # Only redirect if not in debug mode, not on localhost, and not already HTTPS
    host = request.host.split(':')[0]
    if (
        not app.debug
        and request.headers.get('X-Forwarded-Proto', 'http') != 'https'
        and host not in ('127.0.0.1', 'localhost', '::1')
    ):
        url = request.url.replace('http://', 'https://', 1)
        return redirect(url, code=301)

@app.route('/')
def home():
    db = get_db()
    pictures = db.execute('SELECT * FROM pictures').fetchall()
    return render_template('index.html', pictures=pictures)

@app.route('/about')
def about():
    return render_template('about.html')  # About page

@app.route('/portfolio')
def portfolio():
    db = get_db()
    pictures = db.execute('SELECT * FROM pictures').fetchall()
    return render_template('portfolio.html', pictures=pictures)  # Portfolio page

@app.route('/booking', methods=['GET', 'POST'])
def booking():
    if request.method == 'POST':
        # Collect form data
        name = request.form['name']
        phone = request.form['phone']
        date = request.form['date']
        message = request.form.get('message', '')
        
        # Create the email message
        msg = Message(
            'New Tattoo Booking Request',
            recipients=['blaqfeather115@gmail.com']
        )
        
        # Email body content
        msg.body = f"""
        You have a new booking request:

        Name: {name}
        Email: {phone}
        Preferred Date: {date}
        Message: {message}
        """
        
        try:
            mail.send(msg)
            flash('Booking request submitted! We will contact you soon.', 'success')
            return redirect('/thank-you')
        except Exception as e:
            print(f"Error sending email: {e}")
            flash('There was an error sending your booking request. Please try again.', 'error')
            return redirect(url_for('booking'))

    return render_template('booking.html')

@app.route('/thank-you')
def thank_you():
    return render_template('thank-you.html')  # Thank you page after form submission

@app.route('/reviews')
def reviews():
    db = get_db()
    # Only show approved reviews to the public
    reviews = db.execute('SELECT * FROM reviews WHERE approved=1').fetchall()
    return render_template('reviews.html', reviews=reviews)

# Allow clients to submit reviews
@app.route('/reviews/add', methods=['POST'])
def add_client_review():
    author = request.form['author']
    text = request.form['text']
    db = get_db()
    # All new reviews are unapproved by default
    db.execute('INSERT INTO reviews (author, text, approved) VALUES (?, ?, 0)', (author, text))
    db.commit()
    flash('Review submitted! Awaiting approval.', 'success')
    return redirect(url_for('reviews'))

@app.route('/testimonials')
def testimonials():
    return redirect(url_for('reviews'))

@app.route('/contact')
def contact():
    return render_template('contact.html')  # Contact page

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    ip = request.remote_addr
    if is_locked_out(ip):
        flash('Too many failed attempts. Try again later.')
        return render_template('admin_login.html')
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        user = db.execute('SELECT * FROM admin WHERE username=?', (username,)).fetchone()
        if user and check_password_hash(user['password_hash'], password):
            session['admin_logged_in'] = True
            FAILED_LOGINS.pop(ip, None)
            return redirect(url_for('admin_dashboard'))
        else:
            # Increment failed attempts
            attempts, last_attempt = FAILED_LOGINS.get(ip, (0, datetime.now()))
            FAILED_LOGINS[ip] = (attempts + 1, datetime.now())
            flash('Invalid credentials')
    return render_template('admin_login.html')

@app.route('/admin/logout')
@login_required
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect(url_for('admin_login'))

@app.route('/admin/reset_password', methods=['GET', 'POST'])
def admin_reset_password():
    if request.method == 'POST':
        email = request.form['email']
        db = get_db()
        user = db.execute('SELECT * FROM admin WHERE username=?', (email,)).fetchone()
        # Always show generic message to prevent user enumeration
        if user:
            import secrets
            token = secrets.token_urlsafe(32)
            expiry = int(time.time()) + 3600  # 1 hour from now
            db.execute('UPDATE admin SET reset_token=?, reset_token_expiry=? WHERE username=?', (token, expiry, email))
            db.commit()
            reset_url = url_for('admin_reset_with_token', token=token, _external=True)
            msg = Message('Password Reset Request', recipients=[email])
            msg.body = f"To reset your password, visit: {reset_url}\nThis link expires in 1 hour."
            try:
                mail.send(msg)
            except Exception:
                pass  # Do not reveal email status
        flash('If this email exists, a reset link has been sent.', 'success')
        return redirect(url_for('admin_login'))
    return render_template('admin_reset_password.html')

@app.route('/admin/reset/<token>', methods=['GET', 'POST'])
def admin_reset_with_token(token):
    db = get_db()
    user = db.execute('SELECT * FROM admin WHERE reset_token=?', (token,)).fetchone()
    # Check token and expiry
    if not user or not user['reset_token_expiry'] or int(user['reset_token_expiry']) < int(time.time()):
        flash('Invalid or expired reset token.', 'error')
        return redirect(url_for('admin_login'))
    if request.method == 'POST':
        new_password = request.form['password']
        # Enforce minimum password length
        if len(new_password) < 8:
            flash('Password must be at least 8 characters long.', 'error')
            return render_template('admin_set_new_password.html', token=token)
        db.execute('UPDATE admin SET password_hash=?, reset_token=NULL, reset_token_expiry=NULL WHERE id=?',
                   (generate_password_hash(new_password), user['id']))
        db.commit()
        flash('Password reset successful. Please log in.', 'success')
        return redirect(url_for('admin_login'))
    return render_template('admin_set_new_password.html', token=token)

@app.route('/admin')
@login_required
def admin_dashboard():
    db = get_db()
    pictures = db.execute('SELECT * FROM pictures').fetchall()
    # Admin sees all reviews, including unapproved
    reviews = db.execute('SELECT * FROM reviews').fetchall()
    return render_template('admin_dashboard.html', pictures=pictures, reviews=reviews)

@app.route('/admin/pictures/add', methods=['POST'])
@login_required
def add_picture():
    file = request.files.get('picture')
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(UPLOAD_FOLDER, filename))
        db = get_db()
        db.execute('INSERT INTO pictures (filename) VALUES (?)', (filename,))
        db.commit()
        flash('Picture added!', 'success')
    else:
        flash('Invalid file type.', 'error')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/pictures/delete/<int:pic_id>', methods=['POST'])
@login_required
def delete_picture(pic_id):
    db = get_db()
    pic = db.execute('SELECT filename FROM pictures WHERE id=?', (pic_id,)).fetchone()
    if pic:
        filepath = os.path.join(UPLOAD_FOLDER, pic['filename'])
        if os.path.exists(filepath):
            os.remove(filepath)
        db.execute('DELETE FROM pictures WHERE id=?', (pic_id,))
        db.commit()
        flash('Picture deleted.', 'success')
    else:
        flash('Picture not found.', 'error')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/reviews/add', methods=['POST'])
@login_required
def admin_add_review():
    author = request.form['author']
    text = request.form['text']
    db = get_db()
    # All new reviews added by admin are approved by default
    db.execute('INSERT INTO reviews (author, text, approved) VALUES (?, ?, 1)', (author, text))
    db.commit()
    flash('Review added!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/reviews/delete/<int:review_id>', methods=['POST'])
@login_required
def delete_review(review_id):
    db = get_db()
    db.execute('DELETE FROM reviews WHERE id=?', (review_id,))
    db.commit()
    flash('Review deleted.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/reviews/approve/<int:review_id>', methods=['POST'])
@login_required
def approve_review(review_id):
    db = get_db()
    db.execute('UPDATE reviews SET approved=1 WHERE id=?', (review_id,))
    db.commit()
    flash('Review approved.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/reviews/edit/<int:review_id>', methods=['GET', 'POST'])
@login_required
def edit_review(review_id):
    db = get_db()
    if request.method == 'POST':
        author = request.form['author']
        text = request.form['text']
        db.execute('UPDATE reviews SET author=?, text=? WHERE id=?', (author, text, review_id))
        db.commit()
        flash('Review updated!', 'success')
        return redirect(url_for('admin_dashboard'))
    review = db.execute('SELECT * FROM reviews WHERE id=?', (review_id,)).fetchone()
    return render_template('edit_review.html', review=review)

if __name__ == "__main__":
    app.run(debug=True)
    app.run(debug=True)
