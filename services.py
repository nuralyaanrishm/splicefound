# services.py

import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

# Database configuration
db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': '',  
    'database': 'image_detection_db',
    'port': 3306,
    'auth_plugin': 'mysql_native_password'
}

# ----- USER CRUD -----
def create_user(email, password):
    hashed_password = generate_password_hash(password)
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (email, password) VALUES (%s, %s)", (email, hashed_password))
    conn.commit()
    cursor.close()
    conn.close()

def get_user_by_email(email):
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    return user

def get_user_by_id(user_id):
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    return user

def check_user_password(stored_hash, password_input):
    return check_password_hash(stored_hash, password_input)

# ----- DETECTION CRUD -----
def insert_detection(user_id, filename, ela_filename, mask_filename, highlighted_filename, result, tamper_ratio):
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO detections (user_id, filename, ela_filename, mask_filename, highlighted_filename, result, tamper_ratio, timestamp)
        VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())
    """, (user_id, filename, ela_filename, mask_filename, highlighted_filename, result, tamper_ratio))
    conn.commit()
    cursor.close()
    conn.close()

def get_detections_by_user(user_id):
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM detections WHERE user_id = %s ORDER BY timestamp DESC", (user_id,))
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return rows

def get_detection_by_id(detection_id, user_id):
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)
    cursor.execute('''
        SELECT d.*, u.email FROM detections d 
        JOIN users u ON d.user_id = u.id 
        WHERE d.id = %s AND u.id = %s
    ''', (detection_id, user_id))
    detection = cursor.fetchone()
    cursor.close()
    conn.close()
    return detection
