import sqlite3
import hashlib

conn = sqlite3.connect('site.db')
c = conn.cursor()
c.execute('''
CREATE TABLE IF NOT EXISTS pictures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL
)
''')
c.execute('''
CREATE TABLE IF NOT EXISTS reviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    author TEXT NOT NULL,
    text TEXT NOT NULL
)
''')
c.execute('''
CREATE TABLE IF NOT EXISTS admin (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL
)
''')

admin_username = 'admin'
admin_password = 'password'
password_hash = hashlib.sha256(admin_password.encode()).hexdigest()
c.execute('INSERT OR IGNORE INTO admin (username, password_hash) VALUES (?, ?)', (admin_username, password_hash))

conn.commit()
conn.close()
