import os
import io
import secrets
import mysql.connector
import numpy as np
import cv2
from PIL import Image, ImageChops, ImageEnhance, ImageFilter
from flask import Flask, request, render_template, redirect, url_for, flash, session, send_file
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from fpdf import FPDF
from datetime import datetime
from functools import wraps
from flask import Flask, request, send_file, render_template
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import time
from io import BytesIO
from fpdf import FPDF
from flask import send_file
from datetime import datetime
from PIL import ExifTags

from flask import Flask
app = Flask(__name__)

# === Configuration ===
db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': '',
    'database': 'image_detection_db',
    'port': 3306,
    'auth_plugin': 'mysql_native_password'
}

app = Flask(__name__, template_folder=os.path.abspath('templates'))
app.secret_key = secrets.token_hex(16)
CORS(app)

UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# === Helper Functions ===
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'user_id' not in session:
            flash('Login first')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrap

# === Routes ===
@app.route('/')
@login_required
def home():
    return render_template('home.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        hashed_password = generate_password_hash(password)
        
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        if cursor.fetchone():
            flash('Email already registered. Please login.')
            return redirect(url_for('login'))

        cursor.execute("INSERT INTO users (email, password) VALUES (%s, %s)", (email, hashed_password))
        conn.commit()
        cursor.close()
        conn.close()
        flash('Account created! Please log in.')
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        conn = mysql.connector.connect(**db_config)
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        cur.close()
        conn.close()
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['email'] = user['email']
            return redirect(url_for('home'))
        else:
            flash('Invalid login credentials. Please try again.', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    file = request.files.get('image')
    if not file or file.filename == '':
        flash('No file selected')
        return redirect(url_for('home'))

    if allowed_file(file.filename):
        filename = datetime.now().strftime('%Y%m%d_%H%M%S_') + secure_filename(file.filename)
        path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(path)

        with open(path, 'rb') as f:
            img_data = f.read()

        result = analyze_image_internal(img_data, filename)

        conn = mysql.connector.connect(**db_config)
        cur = conn.cursor()
        cur.execute("INSERT INTO detections (user_id, image_path, result, tamper_ratio) VALUES (%s, %s, %s, %s)", 
            (session['user_id'], filename, result['result'], float(result['tamper_ratio'])))

        conn.commit()
        detection_id = cur.lastrowid
        cur.close()
        conn.close()

        return redirect(url_for('result', detection_id=detection_id))

    flash('Invalid file type')
    return redirect(url_for('home'))

@app.route('/result/<int:detection_id>')
@login_required
def result(detection_id):
    conn = mysql.connector.connect(**db_config)
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM detections WHERE id = %s AND user_id = %s", (detection_id, session['user_id']))
    data = cur.fetchone()
    cur.close()
    conn.close()

    if data:
        filename = data['image_path']
        data['original'] = filename
        data['ela'] = f"ela_{filename}"
        data['mask'] = f"mask_{filename}"
        data['highlighted'] = f"highlighted_{filename}"
        return render_template('result.html', detection=data)

    flash('Detection not found.')
    return redirect(url_for('home'))

@app.route('/history')
@login_required
def history():
    conn = mysql.connector.connect(**db_config)
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM detections WHERE user_id = %s ORDER BY timestamp DESC", (session['user_id'],))
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('history.html', detections=rows)

@app.route('/generate_report/<int:detection_id>')
@login_required
def generate_report(detection_id):
    conn = mysql.connector.connect(**db_config)
    cur = conn.cursor(dictionary=True)
    cur.execute('''
        SELECT d.*, u.email FROM detections d 
        JOIN users u ON d.user_id = u.id 
        WHERE d.id = %s AND u.id = %s
    ''', (detection_id, session['user_id']))
    d = cur.fetchone()
    cur.close()
    conn.close()

    if not d:
        flash("Report not found")
        return redirect(url_for('history'))

    # Image Paths
    original_image_path = os.path.join(app.config['UPLOAD_FOLDER'], d['image_path'])
    ela_image_path = os.path.join(app.config['UPLOAD_FOLDER'], f"ela_{d['image_path']}")
    highlighted_image_path = os.path.join(app.config['UPLOAD_FOLDER'], f"highlighted_{d['image_path']}")

    # Detection Result (e.g., Tampered or Not)
    detection_result = "Tampered" if d.get('result') == 'Tampered' else "Genuine"

    # --- Insert EXIF extraction code here ---
    image = Image.open(original_image_path)

    camera_model = "Unspecified"
    date_taken = "N/A"
    file_format = image.format

    exif = {}  # Initialize

    exif_data = image._getexif()
    if exif_data:
        exif = {
            ExifTags.TAGS.get(tag): value
            for tag, value in exif_data.items()
            if tag in ExifTags.TAGS
        }
        camera_model = exif.get('Model', camera_model)
        date_taken = exif.get('DateTimeOriginal', exif.get('DateTime', date_taken))

    file_size = os.path.getsize(original_image_path)

    # --- End EXIF extraction ---
    
    # Create PDF document
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "SpliceFound: Image Splicing Detection Report", ln=True, align='C')
    pdf.set_font("Arial", size=12)
    
    # Add dynamic data into the report
    pdf.cell(0, 10, f"User: {session['email']}", ln=True)
    pdf.cell(0, 10, f"Date report generated: {datetime.now().strftime('%d/%m/%Y || %H:%M:%S')}", ln=True)
    pdf.ln(10)
    pdf.multi_cell(0, 10, "This report presents a comparison of original and processed images using the SpliceFound image splicing detection tool. The purpose is to demonstrate the effectiveness of the tool in identifying tampered regions in digital images.")
    pdf.ln(10)

    # Add detection result
    pdf.cell(0, 10, f"Detection Result: {detection_result}", ln=True)
    pdf.ln(10)

    # Add original image
    pdf.cell(0, 10, "Original Image:", ln=True)
    pdf.image(original_image_path, w=100)  # Adjust image size as needed
    pdf.ln(10)


    # Add original with white traces
    pdf.cell(0, 10, "Result Image (Tampered Areas Highlighted):", ln=True)
    pdf.image(highlighted_image_path, w=100)  # Adjust the size as needed
    pdf.ln(10)

    # Add metadata
    pdf.cell(0, 10, "METADATA:", ln=True)
    pdf.cell(0, 10, f"File name: {d['image_path']}", ln=True)
    pdf.cell(0, 10, f"Camera model: {camera_model}", ln=True)
    pdf.cell(0, 10, f"Date taken: {date_taken}", ln=True)
    pdf.cell(0, 10, f"File format: {file_format}", ln=True)
    pdf.cell(0, 10, f"File size: {file_size} bytes", ln=True)
    pdf.ln(10)


    # Additional Information
    pdf.cell(0, 10, "Additional Information", ln=True)
    pdf.cell(0, 10, "Detection Technique: Error Level Analysis (ELA)", ln=True)
    pdf.cell(0, 10, "Tamper Highlighting Method: Colorized Overlay", ln=True)
    pdf.cell(0, 10, "Tool Version: SpliceFound v1.0", ln=True)

    # Save PDF to a buffer
    buf = BytesIO()
    buf.write(pdf.output(dest='S').encode('latin1'))
    buf.seek(0)

    # Return the generated PDF as an attachment
    return send_file(buf, as_attachment=True, download_name=f"report_{detection_id}.pdf")

# === Image Analysis Functions ===
def perform_ela(image_path, quality=85):
    original = Image.open(image_path).convert("RGB")
    buffer = io.BytesIO()
    original.save(buffer, "JPEG", quality=quality)
    buffer.seek(0)
    compressed = Image.open(buffer)

    ela_image = ImageChops.difference(original, compressed)

    extreme = ela_image.getextrema()
    max_diff = max([ex[1] for ex in extreme])
    scale = 60.0 if max_diff == 0 else min(255.0 / max_diff, 60.0)

    boosted_scale = scale * 1.8
    ela_enhanced_color = ImageEnhance.Brightness(ela_image).enhance(boosted_scale).filter(ImageFilter.GaussianBlur(radius=2))

    return original, ela_enhanced_color

def create_tamper_mask(ela_color_image, threshold_value=30):
    ela_array = np.array(ela_color_image).astype(np.uint8)
    ela_gray = cv2.cvtColor(ela_array, cv2.COLOR_RGB2GRAY)
    _, mask = cv2.threshold(ela_gray, threshold_value, 255, cv2.THRESH_BINARY)
    return Image.fromarray(mask)

def is_probably_tampered(mask_image, threshold_ratio=0.02):
    mask_array = np.array(mask_image)
    white_pixels = np.sum(mask_array == 255)
    total_pixels = mask_array.size
    ratio = white_pixels / total_pixels
    print(f"[INFO] Tampered pixel ratio: {ratio:.4f}")
    return ratio > threshold_ratio, ratio

def overlay_mask_on_original(original_img, mask_img, color=(255, 255, 255)):
    original_array = np.array(original_img).copy()
    mask_array = np.array(mask_img)
    overlay_indices = np.where(mask_array == 255)
    original_array[overlay_indices] = color
    return Image.fromarray(original_array)

def analyze_image_internal(img_data, filename):
    path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    with open(path, 'wb') as f:
        f.write(img_data)

    original, ela_color = perform_ela(path)
    tamper_mask = create_tamper_mask(ela_color)
    highlighted = overlay_mask_on_original(original, tamper_mask)

    ela_path = os.path.join(app.config['UPLOAD_FOLDER'], f"ela_{filename}")
    mask_path = os.path.join(app.config['UPLOAD_FOLDER'], f"mask_{filename}")
    highlighted_path = os.path.join(app.config['UPLOAD_FOLDER'], f"highlighted_{filename}")

    ela_color.save(ela_path)
    tamper_mask.save(mask_path)
    highlighted.save(highlighted_path)

    tampered, ratio = is_probably_tampered(tamper_mask)
    result = 'Tampered' if tampered else 'Genuine'

    return {
        'result': result,
        'tamper_ratio': ratio
    }

# === Start Server ===
if __name__ == '__main__':
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
    app.run(debug=True)
