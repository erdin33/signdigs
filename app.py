from flask import Flask, render_template, request, send_file, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey, Ed448PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.fernet import Fernet
from urllib.parse import urlencode
import qrcode
import os
import uuid
import io
import functools
import werkzeug.security
import base64
import hashlib
import fitz
import smtplib
import re
import time
from werkzeug.security import generate_password_hash, check_password_hash
from email.message import EmailMessage
from PyPDF2 import PdfReader, PdfWriter
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.utils import ImageReader
from reportlab.lib.colors import black
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev_secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'digisignkel11@gmail.com')
# Gunakan app password untuk Gmail, bukan password akun Gmail biasa
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', 'bubi icam yjag ugfg')  # Password yang dihasilkan Google


UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')  # path absolut ke folder uploads
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Pastikan folder uploads ada
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)


def get_fernet_key_from_password(password: str) -> bytes:
    # Gunakan SHA-256 untuk menghasilkan key 32-byte
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())

def encrypt_private_key(private_key_bytes: bytes, password: str) -> bytes:
    key = get_fernet_key_from_password(password)
    f = Fernet(key)
    return f.encrypt(private_key_bytes)

def decrypt_private_key(encrypted_key: bytes, password: str) -> bytes:
    key = get_fernet_key_from_password(password)
    f = Fernet(key)
    return f.decrypt(encrypted_key)


# Fungsi pembuatan QR code
def create_verification_qr(username, public_key_hex, institution=None, email=None, doc_id=None):
    """
    Membuat QR code dengan URL verifikasi yang hanya menggunakan token
    """
    # Gunakan HTTP untuk pengembangan lokal
    base_url = "https://18l41cx3-5000.asse.devtunnels.ms/verify_qr"
    
    # Buat token unik
    unique_token = str(uuid.uuid4())[:12]  # Gunakan 12 karakter untuk keamanan lebih baik
    
    # Timestamp untuk pencatatan waktu
    timestamp = int(time.time())
    
    # Simpan informasi verifikasi di database menggunakan token sebagai kunci
    verification = VerificationToken(
        token=unique_token,
        username=username,
        public_key=public_key_hex[:40],
        timestamp=timestamp,
        institution=institution,
        email=email,
        doc_id=doc_id
    )
    db.session.add(verification)
    db.session.commit()
    
    # Buat URL hanya dengan token
    verification_url = f"{base_url}?token={unique_token}"
    
    # Buat QR code
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=4,
    )
    qr.add_data(verification_url)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Konversi QR code ke BytesIO
    img_io = io.BytesIO()
    img.save(img_io, format='PNG')
    img_io.seek(0)
    
    return img_io


def send_signature_email(recipient_email, username, doc_name, sign_time, file_path):
    try:
        msg = EmailMessage()
        msg['Subject'] = f'Dokumen Ditandatangani oleh {username}'
        msg['From'] = app.config['MAIL_USERNAME']
        msg['To'] = recipient_email

        # Isi email
        msg.set_content(f"""
        Halo,

        Dokumen Anda '{doc_name}' telah berhasil ditandatangani oleh {username}.
        Waktu penandatanganan: {sign_time} UTC

        Dokumen yang sudah ditandatangani terlampir dalam email ini. Anda dapat mengunduhnya langsung.

        Salam,
        Tim DigiSign
        """.strip())

        # Tambahkan file PDF sebagai lampiran
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        # Lampirkan file dengan nama yang jelas
        msg.add_attachment(file_data, maintype='application', subtype='pdf', filename=doc_name)

        # Kirim email
        with smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT']) as smtp:
            smtp.starttls()
            smtp.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
            smtp.send_message(msg)
            return True
    except Exception as e:
        print(f"Gagal mengirim email: {e}")
        return False


db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    public_key = db.Column(db.LargeBinary, nullable=False)
    private_key = db.Column(db.LargeBinary, nullable=False)
    institution = db.Column(db.String(120), nullable=True)
    email = db.Column(db.String(120), nullable=True)

class SignedDocument(db.Model):
    id = db.Column(db.String(36), primary_key=True)
    filename = db.Column(db.String(120), nullable=False)
    signature = db.Column(db.LargeBinary, nullable=False)
    username = db.Column(db.String(80), db.ForeignKey('user.username'), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False)
    
class VerificationToken(db.Model):
    __table_args__ = {'extend_existing': True}
    
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(20), unique=True, nullable=False)
    username = db.Column(db.String(100), nullable=False)
    public_key = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.Integer, nullable=False)
    institution = db.Column(db.String(100), nullable=True)
    email = db.Column(db.String(100), nullable=True)
    doc_id = db.Column(db.String(100), nullable=True)
    is_used = db.Column(db.Boolean, default=False)
    
    def __repr__(self):
        return f'<Token {self.token}>'
    

def __repr__(self):
        return f'<Token {self.token}>'


@app.context_processor
def inject_now():
    return {'now': datetime.utcnow}

def login_required(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Please login to access this page', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')

    username = request.form['username']
    password = request.form['password']
    confirm_password = request.form['confirm_password']
    institution = request.form['institution']
    email = request.form['email']

    if User.query.filter_by(username=username).first():
        flash('Username already exists', 'error')
        return redirect(url_for('register'))

    if password != confirm_password:
        flash('Passwords do not match', 'error')
        return redirect(url_for('register'))

    private_key = Ed448PrivateKey.generate()
    public_key = private_key.public_key()

    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    
    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    encrypted_priv_bytes = encrypt_private_key(priv_bytes, password)

    qr = qrcode.make(pub_bytes.hex())
    barcode_path = f"{UPLOAD_FOLDER}/{username}_pubkey.png"
    qr.save(barcode_path)

    new_user = User(
        username=username,
        password=werkzeug.security.generate_password_hash(password),
        public_key=pub_bytes,
        private_key=encrypted_priv_bytes,
        institution=institution,
        email=email  # Simpan email user
    ) 
    db.session.add(new_user)
    db.session.commit()

    flash('Registration successful! Please log in', 'success')
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')

    username = request.form['username']
    password = request.form['password']

    user = User.query.filter_by(username=username).first()
    if not user or not werkzeug.security.check_password_hash(user.password, password):
        flash('Invalid username or password', 'error')
        return redirect(url_for('login'))

    session['username'] = username
    flash('Login successful!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    username = session['username']
    qr_path = f"{username}_pubkey.png"
    user_docs = SignedDocument.query.filter_by(username=username).all()
    return render_template('dashboard.html', username=username, qr_path=qr_path, user_docs=user_docs)


# Fungsi untuk menambahkan QR code dengan informasi tambahan ke dokumen PDF
def overlay_signature_to_pdf(barcode_path, original_pdf_path, x, y, target_page=None, username="", institution=""):
    """
    Menambahkan tanda tangan QR code ke PDF dengan informasi tambahan
    """
    packet = io.BytesIO()
    
    # Baca dokumen asli untuk mendapatkan ukuran halaman yang tepat
    doc = fitz.open(original_pdf_path)
    base_pdf = PdfReader(original_pdf_path)
    writer = PdfWriter()
    
    # Proses setiap halaman dalam dokumen
    for page_num in range(len(base_pdf.pages)):
        # Buat canvas baru untuk setiap halaman
        if page_num < len(doc):
            page = doc.load_page(page_num)
            page_width = page.rect.width
            page_height = page.rect.height
        else:
            # Default ke ukuran letter jika halaman tidak ada
            page_width, page_height = letter
        
        # Reset buffer untuk membuat overlay baru
        packet.seek(0)
        packet.truncate(0)
        
        can = canvas.Canvas(packet, pagesize=(page_width, page_height))
        
        # Ukuran QR code yang lebih kecil
        qr_width = 70
        qr_height = 70
        
        # Koordinat y sebenarnya pada canvas (dari bawah halaman)
        canvas_y = y
        
        # Gambar QR code
        can.drawImage(ImageReader(barcode_path), x, canvas_y, width=qr_width, height=qr_height)
        
        # Set font untuk teks
        try:
            pdfmetrics.registerFont(TTFont('Helvetica-Bold', 'Helvetica-Bold.ttf'))
            font_name = 'Helvetica-Bold'
        except:
            font_name = 'Helvetica-Bold'
        
        # Tambahkan teks informasi di bawah QR code
        can.setFont(font_name, 4)
        can.setFillColor(black)
        can.drawString(x - -15, canvas_y - 1, "Signature By DigSign")
        can.drawString(x - -15, canvas_y - 5, f"Signed by: {username}")
        if institution:
            can.drawString(x - -15, canvas_y - 9, f"From: {institution}")
        
        can.save()
        packet.seek(0)
        
        # Overlay QR code ke halaman
        overlay_pdf = PdfReader(packet)
        page = base_pdf.pages[page_num]
        page.merge_page(overlay_pdf.pages[0])
        writer.add_page(page)
    
    return writer


@app.route('/sign', methods=['GET', 'POST'])
@login_required
def sign_pdf():
    if request.method == 'GET':
        return render_template('sign.html')

    username = session['username']
    user = User.query.filter_by(username=username).first()
    file = request.files['pdf']
    password = request.form.get('password')

    if file.filename == '':
        flash('Tidak ada file yang dipilih', 'error')
        return redirect(url_for('sign_pdf'))

    if not password:
        flash('Password diperlukan untuk mendekripsi private key Anda', 'error')
        return redirect(url_for('sign_pdf'))

    try:
        decrypted_key_bytes = decrypt_private_key(user.private_key, password)
        priv_key = Ed448PrivateKey.from_private_bytes(decrypted_key_bytes)
    except Exception as e:
        flash(f'Gagal mendekripsi private key. Password mungkin salah. Error: {str(e)}', 'error')
        return redirect(url_for('sign_pdf'))

    file_path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(file_path)

    x, y, _ = find_signature_position(file_path)
    if x is None or y is None:
        doc = fitz.open(file_path)
        if len(doc) > 0:
            last_page = doc.load_page(len(doc) - 1)
            x, y = 20, 20
        else:
            x, y = 20, 20
    
    # Generate QR code khusus untuk dokumen ini dengan informasi dokumen
    doc_id = str(uuid.uuid4())
    sign_time = datetime.utcnow().isoformat()
    
    # Ambil public key dalam format hex
    pub_key_hex = user.public_key.hex()
    
    # Buat data untuk QR code yang khusus untuk dokumen ini
    doc_data = {
        "doc_id": doc_id,
        "signer": username,
        "institution": user.institution if user.institution else "",
        "time": sign_time,
        "public_key": pub_key_hex
    }
    
    # Buat QR code dengan data URI untuk dokumen ini
    doc_qr_path = f"{UPLOAD_FOLDER}/{doc_id}_verification.png"
    img_io = create_verification_qr(
        username, 
        pub_key_hex, 
        user.institution,
        user.email
    )
    
    with open(doc_qr_path, 'wb') as f:
        f.write(img_io.getvalue())
    
    # Gunakan QR code yang baru dibuat untuk overlay ke dokumen
    writer = overlay_signature_to_pdf(
        doc_qr_path, 
        file_path, 
        x, y, 
        username=username, 
        institution=user.institution
    )

    temp_pdf = io.BytesIO()
    writer.write(temp_pdf)
    pdf_data = temp_pdf.getvalue()

    signature = priv_key.sign(pdf_data)

    # Tambahkan metadata yang lebih lengkap
    writer.add_metadata({
        '/SignedBy': username,
        '/Signature': signature.hex(),
        '/Institution': user.institution if user.institution else "",
        '/SignDate': sign_time,
        '/DocumentID': doc_id,
        '/PublicKey': pub_key_hex
    })

    signed_filename = f"signed_{file.filename}"
    signed_path = os.path.join(UPLOAD_FOLDER, signed_filename)
    with open(signed_path, 'wb') as f:
        writer.write(f)

    new_doc = SignedDocument(
        id=doc_id,
        filename=signed_filename,
        signature=signature,
        username=username,
        timestamp=datetime.utcnow()
    )
    db.session.add(new_doc)
    db.session.commit()
    
    # Kirim email verifikasi jika user memiliki email
    if user.email:
        email_sent = send_signature_email(
            recipient_email=user.email,
            username=username,
            doc_name=signed_filename,
            sign_time=sign_time,
            file_path=signed_path
        )
        if email_sent:
            flash('Dokumen berhasil ditandatangani dan telah dikirim ke email Anda!', 'success')
        else:
            flash('Dokumen berhasil ditandatangani, tetapi gagal mengirim ke email.', 'warning')
    else:
        flash('Dokumen berhasil ditandatangani! (Email notifikasi tidak dikirim karena alamat email tidak tersedia)', 'success')
        
    return send_file(signed_path, as_attachment=True)


@app.route('/about')
def about():
    """Route for the About page"""
    return render_template('about.html')

@app.route('/verify', methods=['GET', 'POST'])
def verify_pdf():
    if request.method == 'GET':
        return render_template('verify.html')

    file = request.files['pdf']
    if file.filename == '':
        flash('No file uploaded', 'error')
        return redirect(url_for('verify_pdf'))

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"verify_{file.filename}")
    file.save(file_path)

    with open(file_path, 'rb') as f:
        reader = PdfReader(f)
        metadata = reader.metadata

        if '/Signature' not in metadata or '/SignedBy' not in metadata:
            result = "Document does not have a digital signature."
            return render_template('verify_result.html', result=result, valid=False)

        signature = bytes.fromhex(metadata['/Signature'])
        username = metadata['/SignedBy']
        institution = metadata.get('/Institution', 'Not specified')
        sign_date = metadata.get('/SignDate', 'Unknown')

        user = User.query.filter_by(username=username).first()
        if not user:
            result = "Signer not found in the system."
            return render_template('verify_result.html', result=result, valid=False)

        pub_key = Ed448PublicKey.from_public_bytes(user.public_key)

        writer = PdfWriter()
        for page in reader.pages:
            writer.add_page(page)

        pdf_bytes = io.BytesIO()
        writer.write(pdf_bytes)
        pdf_data = pdf_bytes.getvalue()

        try:
            pub_key.verify(signature, pdf_data)
            result = f"Document is valid. Signed by: {username} from {user.institution}"
            return render_template('verify_result.html', 
                                  result=result, 
                                  valid=True, 
                                  signer=username, 
                                  institution=user.institution,
                                  sign_date=sign_date)
        except Exception:
            result = "Invalid signature."
            return render_template('verify_result.html', result=result, valid=False)

    
    
@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if 'username' not in session:
        flash('Please login to access this page.', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'GET':
        # Ambil data user dari database menggunakan SQLAlchemy
        user = User.query.filter_by(username=session['username']).first()
        if user:
            return render_template('edit_profile.html', user=user)
        else:
            flash('User not found.', 'error')
            # Ganti 'home' dengan 'index' atau 'dashboard' sesuai halaman utama Anda
            return redirect(url_for('index'))  # atau url_for('dashboard')
    
    elif request.method == 'POST':
        # Ambil data dari form
        new_email = request.form.get('email')
        new_institution = request.form.get('institution')
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Validasi input
        if not new_email:
            flash('Email is required.', 'error')
            return redirect(url_for('edit_profile'))
        
        # Validasi email format
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', new_email):
            flash('Please enter a valid email address.', 'error')
            return redirect(url_for('edit_profile'))
        
        # Ambil data user saat ini
        current_user = User.query.filter_by(username=session['username']).first()
        if not current_user:
            flash('User not found.', 'error')
            # Ganti 'home' dengan 'index' atau 'dashboard' sesuai halaman utama Anda
            return redirect(url_for('index'))  # atau url_for('dashboard')
        
        # Verifikasi password saat ini jika ada perubahan password
        if new_password:
            if not current_password:
                flash('Current password is required to change password.', 'error')
                return redirect(url_for('edit_profile'))
            
            # Verifikasi password saat ini
            if not check_password_hash(current_user.password, current_password):
                flash('Current password is incorrect.', 'error')
                return redirect(url_for('edit_profile'))
            
            # Validasi password baru
            if new_password != confirm_password:
                flash('New passwords do not match.', 'error')
                return redirect(url_for('edit_profile'))
            
            if len(new_password) < 6:
                flash('Password must be at least 6 characters long.', 'error')
                return redirect(url_for('edit_profile'))
        
        # Cek apakah email sudah digunakan oleh user lain
        if new_email != current_user.email:
            existing_user = User.query.filter_by(email=new_email).first()
            if existing_user and existing_user.username != session['username']:
                flash('Email already registered by another user.', 'error')
                return redirect(url_for('edit_profile'))
        
        try:
            # Update data user
            current_user.email = new_email
            if new_institution is not None:  # Allow empty string
                current_user.institution = new_institution
            
            if new_password:
                # Update dengan password baru
                current_user.password = generate_password_hash(new_password)
            
            # Simpan perubahan ke database
            db.session.commit()
            
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('edit_profile'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating profile: {str(e)}', 'error')
            return redirect(url_for('edit_profile'))

@app.route('/download_qr')
@login_required
def download_qr():
    username = session['username']
    barcode_path = f"{UPLOAD_FOLDER}/{username}_pubkey.png"
    return send_file(barcode_path, mimetype='image/png')



@app.route('/verify_qr')
def verify_qr_signature():
    """
    Endpoint untuk verifikasi tanda tangan dari QR code dengan token unik
    """
    token = request.args.get('token')
    
    if not token:
        flash('Token verifikasi tidak ditemukan', 'error')
        return redirect(url_for('verify_pdf'))
    
    # Cari data verifikasi berdasarkan token
    verification = VerificationToken.query.filter_by(token=token).first()
    
    if not verification:
        return render_template('verify_result.html',
                             result="Token verifikasi tidak valid.",
                             valid=False)
    
    # Cari user dengan username dari data verifikasi
    user = User.query.filter_by(username=verification.username).first()
    
    if not user:
        return render_template('verify_result.html',
                             result="Pengguna tidak ditemukan dalam sistem.",
                             valid=False)
    
    # Bandingkan public key dari database dengan yang ada di data verifikasi
    actual_pubkey = user.public_key.hex()
    if not actual_pubkey.startswith(verification.public_key):
        return render_template('verify_result.html',
                             result="Public key tidak sesuai dengan pengguna.",
                             valid=False)
    
    # Konversi timestamp ke format yang lebih mudah dibaca
    from datetime import datetime
    verify_date = datetime.fromtimestamp(verification.timestamp).strftime("%d-%m-%Y %H:%M:%S")
    
    # Jika verifikasi berhasil
    return render_template('verify_result.html',
                         result=f"Tanda tangan valid. Ditandatangani oleh: {verification.username} dari {verification.institution if verification.institution else 'Tidak ada institusi'}",
                         valid=True,
                         signer=verification.username,
                         institution=verification.institution if verification.institution else "Tidak ada institusi",
                         sign_date=verify_date)


@app.route('/download_document/<doc_id>')
@login_required
def download_document(doc_id):
    username = session['username']
    document = SignedDocument.query.filter_by(id=doc_id, username=username).first_or_404()
    file_path = os.path.join(UPLOAD_FOLDER, document.filename)
    
    if not os.path.exists(file_path):
        flash('File tidak ditemukan', 'error')
        return redirect(url_for('dashboard'))
        
    return send_file(file_path, as_attachment=True)




def add_barcode_to_pdf(input_pdf_path, barcode_image_path, output_pdf_path, x, y, page_num=0, width=100, height=40):
    """
    Add barcode to PDF with precise positioning
    
    Parameters:
    - input_pdf_path: Path to the original PDF
    - barcode_image_path: Path to the barcode/QR image
    - output_pdf_path: Path where the output PDF will be saved
    - x, y: Coordinates where to place the barcode (PDF coordinates)
    - page_num: Page number where to add the barcode (0-indexed)
    - width, height: Dimensions of the barcode image
    """
    reader = PdfReader(input_pdf_path)
    writer = PdfWriter()
    
    for i in range(len(reader.pages)):
        page = reader.pages[i]
        
        if i == page_num:
            # Get actual page dimensions
            mediabox = page.mediabox
            page_width = float(mediabox.width)
            page_height = float(mediabox.height)
            
            # Create overlay with barcode
            packet = io.BytesIO()
            # Use the actual page size instead of letter
            can = canvas.Canvas(packet, pagesize=(page_width, page_height))
            
            # Draw the barcode at the exact coordinates - centered at x,y
            # Adjust position to properly center the barcode
            x_centered = x - width/2
            y_centered = y - height/2
            can.drawImage(barcode_image_path, x_centered, y_centered, width=width, height=height, mask='auto')
            can.save()
            
            packet.seek(0)
            overlay_pdf = PdfReader(packet)
            page.merge_page(overlay_pdf.pages[0])
        
        writer.add_page(page)
    
    # Write the output file
    with open(output_pdf_path, "wb") as output_file:
        writer.write(output_file)
    
    return writer

@app.route('/manual_sign', methods=['GET', 'POST'])
@login_required
def manual_sign():
    if request.method == 'GET':
        return render_template('manual_sign.html')
    
    username = session['username']
    user = User.query.filter_by(username=username).first()
    file = request.files['pdf']
    password = request.form.get('password')
    
    # Get coordinates from the form
    x = float(request.form.get('x', 10))
    y = float(request.form.get('y', 10))
    page_num = int(request.form.get('page', 0))  # Default to first page
    
    # Get actual dimensions for barcode (can be adjusted based on user preference)
    barcode_width = float(request.form.get('width', 40))
    barcode_height = float(request.form.get('height', 40))
    
    # Validasi dasar
    if file.filename == '' or not password:
        flash('File dan password diperlukan', 'error')
        return redirect(url_for('manual_sign'))
    
    try:
        decrypted_key_bytes = decrypt_private_key(user.private_key, password)
        priv_key = Ed448PrivateKey.from_private_bytes(decrypted_key_bytes)
    except Exception as e:
        flash(f'Gagal mendekripsi private key: {str(e)}', 'error')
        return redirect(url_for('manual_sign'))
    
    # Save the uploaded PDF
    file_path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(file_path)
    
    # Check if this is a preview request
    is_preview = request.form.get('preview') == 'true'
    
    if is_preview:
        # Create a temporary preview file
        preview_filename = f"preview_{file.filename}"
        preview_path = os.path.join(UPLOAD_FOLDER, preview_filename)
        
        # Create a preview PDF with a placeholder for the barcode
        create_preview_pdf(
            file_path,            # Input PDF
            preview_path,         # Output path for preview
            x, y,                 # Exact coordinates from click
            page_num,             # Page number (0-indexed)
            barcode_width,        # Width of barcode
            barcode_height        # Height of barcode
        )
        
        # Return the preview file
        return send_file(preview_path, as_attachment=False)
    
    # Not a preview, proceed with actual signing
    
    # Generate document ID and signature time
    doc_id = str(uuid.uuid4())
    sign_time = datetime.utcnow().isoformat()
    pub_key_hex = user.public_key.hex()
    
    # Create verification QR code
    doc_qr_path = f"{UPLOAD_FOLDER}/{doc_id}_manual_verification.png"
    img_io = create_verification_qr(
        username, pub_key_hex, user.institution, user.email
    )
    with open(doc_qr_path, 'wb') as f:
        f.write(img_io.getvalue())
    
    # Create temporary file for signed PDF
    signed_filename = f"manual_signed_{file.filename}"
    signed_path = os.path.join(UPLOAD_FOLDER, signed_filename)
    
    # Add barcode directly to PDF using the dedicated function
    add_barcode_to_pdf(
        file_path,             # Input PDF
        doc_qr_path,           # Barcode image
        signed_path,           # Output path
        x, y,                  # Exact coordinates from click
        page_num,              # Page number (0-indexed)
        barcode_width,         # Width of barcode
        barcode_height         # Height of barcode
    )
    
    # Now open the output file and add metadata
    reader = PdfReader(signed_path)
    writer = PdfWriter()
    
    # Copy all pages
    for page in reader.pages:
        writer.add_page(page)
    
    # Create buffer for signing
    temp_pdf = io.BytesIO()
    writer.write(temp_pdf)
    temp_pdf.seek(0)
    pdf_data = temp_pdf.getvalue()
    
    # Generate signature
    signature = priv_key.sign(pdf_data)
    
    # Add metadata to the PDF
    writer.add_metadata({
        '/SignedBy': username,
        '/Signature': signature.hex(),
        '/Institution': user.institution or "",
        '/SignDate': sign_time,
        '/DocumentID': doc_id,
        '/PublicKey': pub_key_hex,
        '/SignatureCoords': f"x={x},y={y},page={page_num}"
    })
    
    # Write the final PDF with metadata
    with open(signed_path, 'wb') as f:
        writer.write(f)
    
    # Add record to database
    db.session.add(SignedDocument(
        id=doc_id,
        filename=signed_filename,
        signature=signature,
        username=username,
        timestamp=datetime.utcnow()
    ))
    db.session.commit()
    
    flash('Dokumen berhasil ditandatangani dengan klik.', 'success')
    return send_file(signed_path, as_attachment=True)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)