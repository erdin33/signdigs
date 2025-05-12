from flask import Flask, render_template, request, send_file, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey, Ed448PublicKey
from cryptography.hazmat.primitives import serialization
import qrcode
import os
import uuid
import io
import functools
import werkzeug.security
from PyPDF2 import PdfReader, PdfWriter
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.utils import ImageReader
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev_secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    public_key = db.Column(db.LargeBinary, nullable=False)
    private_key = db.Column(db.LargeBinary, nullable=False)

class SignedDocument(db.Model):
    id = db.Column(db.String(36), primary_key=True)
    filename = db.Column(db.String(120), nullable=False)
    signature = db.Column(db.LargeBinary, nullable=False)
    username = db.Column(db.String(80), db.ForeignKey('user.username'), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False)

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

    qr = qrcode.make(pub_bytes.hex())
    barcode_path = f"{UPLOAD_FOLDER}/{username}_pubkey.png"
    qr.save(barcode_path)

    new_user = User(
        username=username,
        password=werkzeug.security.generate_password_hash(password),
        public_key=pub_bytes,
        private_key=priv_bytes
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

def overlay_barcode_to_pdf(barcode_path, original_pdf):
    packet = io.BytesIO()
    can = canvas.Canvas(packet, pagesize=letter)
    can.drawImage(ImageReader(barcode_path), 400, 100, width=150, height=150)
    can.save()
    packet.seek(0)

    overlay_pdf = PdfReader(packet)
    base_pdf = PdfReader(original_pdf)
    writer = PdfWriter()

    first_page = base_pdf.pages[0]
    first_page.merge_page(overlay_pdf.pages[0])
    writer.add_page(first_page)

    for page in base_pdf.pages[1:]:
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

    if file.filename == '':
        flash('No file selected', 'error')
        return redirect(url_for('sign_pdf'))

    priv_key = Ed448PrivateKey.from_private_bytes(user.private_key)

    file_path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(file_path)

    barcode_path = f"{UPLOAD_FOLDER}/{username}_pubkey.png"
    writer = overlay_barcode_to_pdf(barcode_path, file_path)

    temp_pdf = io.BytesIO()
    writer.write(temp_pdf)
    pdf_data = temp_pdf.getvalue()

    signature = priv_key.sign(pdf_data)

    writer.add_metadata({
        '/SignedBy': username,
        '/Signature': signature.hex()
    })

    signed_path = os.path.join(UPLOAD_FOLDER, f"signed_{file.filename}")
    with open(signed_path, 'wb') as f:
        writer.write(f)

    doc_id = str(uuid.uuid4())
    new_doc = SignedDocument(
        id=doc_id,
        filename=f"signed_{file.filename}",
        signature=signature,
        username=username,
        timestamp=datetime.utcnow()
    )
    db.session.add(new_doc)
    db.session.commit()

    flash('Document signed successfully!', 'success')
    return send_file(signed_path, as_attachment=True)

@app.route('/verify', methods=['GET', 'POST'])
def verify_pdf():
    if request.method == 'GET':
        return render_template('verify.html')

    file = request.files['pdf']
    if file.filename == '':
        flash('No file uploaded', 'error')
        return redirect(url_for('verify_pdf'))

    file_path = os.path.join(UPLOAD_FOLDER, f"verify_{file.filename}")
    file.save(file_path)

    with open(file_path, 'rb') as f:
        reader = PdfReader(f)
        metadata = reader.metadata

        if '/Signature' not in metadata or '/SignedBy' not in metadata:
            result = "Document does not have a digital signature."
            return render_template('verify_result.html', result=result, valid=False)

        signature = bytes.fromhex(metadata['/Signature'])
        username = metadata['/SignedBy']

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
            result = f"Document is valid. Signed by: {username}"
            return render_template('verify_result.html', result=result, valid=True, signer=username)
        except Exception:
            result = "Invalid signature."
            return render_template('verify_result.html', result=result, valid=False)

@app.route('/download_qr')
@login_required
def download_qr():
    username = session['username']
    barcode_path = f"{UPLOAD_FOLDER}/{username}_pubkey.png"
    return send_file(barcode_path, mimetype='image/png')

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

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
