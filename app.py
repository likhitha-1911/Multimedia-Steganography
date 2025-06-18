from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from datetime import timedelta
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from routes import auth_bp
from stego.image_stego import encode_image, decode_image
from stego.audio_stego import encode_audio, decode_audio
from stego.video_stego import encode_video, decode_video
from flask import Flask, render_template, request, jsonify
from stego.quantum_stego.quantum_encode import QuantumEncoder
from stego.quantum_stego.quantum_decode import QuantumDecoder
from database.models import db, User, Log
import sqlite3
import os
from werkzeug.utils import secure_filename
from utils.keygen import generate_rsa_keys
from flask_migrate import Migrate
import base64

VALID_METHODS = ['AES', 'DES', 'RSA', 'ECC']

app = Flask(__name__)
quantum_encoder = QuantumEncoder()
quantum_decoder = QuantumDecoder()
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_PERMANENT'] = False
app.permanent_session_lifetime = timedelta(minutes=1)  # Auto-logout after 1 min
app.config['SESSION_TYPE'] = 'filesystem'
# Add this with your other config settings
app.config['QUANTUM_STEGO_FOLDER'] = os.path.join('static', 'quantum_stego')
os.makedirs(app.config['QUANTUM_STEGO_FOLDER'], exist_ok=True)
db.init_app(app)
migrate = Migrate(app, db)
app.register_blueprint(auth_bp)
login_manager = LoginManager()
login_manager.login_view = 'auth.login'
login_manager.init_app(app)

@app.before_request
def require_login():
    allowed_routes = ['auth.login', 'auth.register']  # Add any more public endpoints here
    if request.endpoint not in allowed_routes and not current_user.is_authenticated:
        return redirect(url_for('auth.login'))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/admin')
@login_required
def admin_panel():
    if not current_user.is_admin:
        flash("Access Denied: Admins only", "danger")
        return redirect(url_for('dashboard'))

    users = User.query.all()
    logs = Log.query.order_by(Log.timestamp.desc()).all()
    return render_template('admin_panel.html', users=users, logs=logs)

@app.route('/admin/update_user/<int:user_id>', methods=['POST'])
@login_required
def update_user(user_id):
    if not current_user.is_admin:
        flash("Access Denied", "danger")
        return redirect(url_for('dashboard'))

    user = User.query.get_or_404(user_id)
    user.email = request.form['email']
    user.is_admin = True if request.form['is_admin'] == '1' else False

    try:
        db.session.commit()
        flash("User updated successfully!", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"[ERROR] {str(e)}", "danger")

    return redirect(url_for('admin_panel'))

@app.route('/admin/delete_user/<int:user_id>')
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash("Access Denied", "danger")
        return redirect(url_for('dashboard'))

    user = User.query.get_or_404(user_id)

    try:
        db.session.delete(user)
        db.session.commit()
        flash("User deleted successfully!", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"[ERROR] {str(e)}", "danger")

    return redirect(url_for('admin_panel'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Fetch logs using SQLAlchemy ORM
    logs = Log.query.filter_by(user_id=current_user.id).order_by(Log.timestamp.desc()).limit(10).all()

    return render_template('dashboard.html', logs=logs)

@app.route('/services')
@login_required
def services():
    return render_template('services.html')

app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/image_stego', methods=['GET', 'POST'])
@login_required
def image_stego():
    decrypted_message = None
    stego_image_url = None

    if request.method == "GET" and request.args.get("generate_keys") == "rsa":
        public_key, private_key = generate_rsa_keys()
        return render_template("image.html", public_key=public_key, private_key=private_key)

    if request.method == 'POST':
        action = request.form.get('action')
        encryption_method = request.form.get('encryption', '').strip().upper()
        encryption_key = request.form.get('key', '').strip()

        if not encryption_method or not encryption_key:
            flash("[ERROR] Encryption method or key is missing!", "danger")
            return redirect(url_for('image_stego'))

        if action == 'encrypt':
            session['encryption_method'] = encryption_method  # Store encryption method in session

            image_file = request.files['image']
            message = request.form['message']

            if image_file and allowed_file(image_file.filename):
                stego_folder = os.path.join('static', 'stego_images')
                os.makedirs(stego_folder, exist_ok=True)
                stego_path = os.path.join(stego_folder, f"stego_{secure_filename(image_file.filename)}")

                try:
                    # Call encode_image function with encryption
                    stego_image = encode_image(image_file, message, encryption_method, encryption_key, stego_path)
                    log_action('Encrypted Image', image_file.filename)

                    stego_image_url = url_for('static', filename=f'stego_images/{os.path.basename(stego_path)}')

                    return render_template('image.html', stego_image_url=stego_image_url)

                except Exception as e:
                    flash(f"[ERROR] {str(e)}", "danger")
                    return redirect(url_for('image_stego'))

        elif action == 'decrypt':
            image_file = request.files['image']
            if image_file and allowed_file(image_file.filename):
                image_path = os.path.join('static', 'stego_images', secure_filename(image_file.filename))
                image_file.save(image_path)

                # Get the encryption method from the session
                encryption_method = request.form.get('encryption', '').strip().upper()

                if not encryption_method:
                    flash("[ERROR] Encryption method is missing for decryption!", "danger")
                    return redirect(url_for('image_stego'))

                try:
                    # Call decode_image function with decryption
                    decrypted_message = decode_image(image_file, encryption_method, encryption_key)
                    log_action('Decrypted Image', image_file.filename)

                    return render_template('image.html', decrypted_message=decrypted_message)

                except Exception as e:
                    flash(f"[ERROR] {str(e)}", "danger")
                    return redirect(url_for('image_stego'))

    return render_template('image.html', decrypted_message=decrypted_message, stego_image_url=stego_image_url)

@app.route('/audio_stego', methods=['GET', 'POST'])
@login_required
def audio_stego():
    stego_audio_url = None
    if request.method == 'POST':
        action = request.form.get('action')
        encryption_method = request.form['encryption'].strip().upper()
        encryption_key = request.form['key']

        # Validate encryption method
        if encryption_method not in VALID_METHODS:
            flash(f"[ERROR] Invalid encryption method: {encryption_method}", "danger")
            return redirect(url_for('audio_stego'))

        if action == 'encrypt':
            audio_file = request.files['audio']
            message = request.form['message']

            if not audio_file or not message:
                flash("[ERROR] Please provide both an audio file and a message.", "danger")
                return redirect(url_for('audio_stego'))

            # Ensure that the uploaded file is saved properly
            os.makedirs(os.path.join('static', 'stego_audio'), exist_ok=True)
            stego_path = os.path.join('static', 'stego_audio', f"stego_{secure_filename(audio_file.filename)}")
            
            try:
                encrypted_message = encode_audio(audio_file, message, encryption_key, encryption_method, stego_path)
                log_action('Encrypted Audio', audio_file.filename)  # Log the action (adjust if needed)
                stego_audio_url = stego_path  # Display the stego audio file path in the template
                return render_template('audio.html', encrypted_audio=encrypted_message, stego_audio_url=stego_audio_url)
            except Exception as e:
                flash(f"[ERROR] {str(e)}", "danger")

        elif action == 'decrypt':
            audio_file = request.files['audio']
            if audio_file:
                audio_path = os.path.join('static', 'stego_audio', secure_filename(audio_file.filename))
                audio_file.save(audio_path)
                try:
                    decrypted_message = decode_audio(audio_path, encryption_key, encryption_method)
                    log_action('Decrypted Audio', audio_file.filename)  # Log the action (adjust if needed)
                    return render_template('audio.html', decrypted_message=decrypted_message)
                except Exception as e:
                    flash(f"[ERROR] {str(e)}", "danger")

    return render_template('audio.html', stego_audio_url=stego_audio_url)

@app.route('/video_stego', methods=['GET', 'POST'])
@login_required
def video_stego():
    if request.method == 'POST':
        action = request.form.get('action')
        
        # Handle both encryption and decryption method fields
        encryption_method = request.form.get('encryption') or request.form.get('encryption_method')
        encryption_method = encryption_method.strip().upper() if encryption_method else None
        encryption_key = request.form.get('key')

        if not encryption_method or encryption_method not in VALID_METHODS:
            flash(f"Invalid encryption method. Please use one of: {', '.join(VALID_METHODS)}", "danger")
            return redirect(url_for('video_stego'))

        if action == 'encrypt':
            video_file = request.files['video']
            message = request.form.get('message')

            if video_file and message:
                try:
                    upload_path = os.path.join('static', 'video_stego', secure_filename(video_file.filename))
                    video_file.save(upload_path)
                    stego_path = os.path.join('static', 'video_stego', f"stego_{secure_filename(video_file.filename)}")
                    
                    encrypted = encode_video(upload_path, message, encryption_key, encryption_method, stego_path)
                    log_action('Encrypted Video', video_file.filename)
                    
                    return render_template('video.html', 
                                        stego_video_url=url_for('static', 
                                        filename=f'video_stego/{os.path.basename(stego_path)}'))
                except Exception as e:
                    flash(f"Encryption failed: {str(e)}", "danger")

        elif action == 'decrypt':
            video_file = request.files['video']
            if video_file:
                try:
                    upload_path = os.path.join('static', 'video_stego', secure_filename(video_file.filename))
                    video_file.save(upload_path)
                    
                    decrypted = decode_video(upload_path, encryption_key, encryption_method)
                    
                    if decrypted.startswith(("Failed", "Error")):
                        flash(decrypted, "danger")
                    else:
                        log_action('Decrypted Video', video_file.filename)
                        return render_template('video.html', 
                                            decrypted_message=decrypted)
                except Exception as e:
                    flash(f"Decryption error: {str(e)}", "danger")

    return render_template('video.html')

@app.route('/quantum', methods=['GET', 'POST'])
def quantum_stego():
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'entangle':
            result = quantum_encoder.create_entanglement()
            return jsonify(result)
            
        elif action == 'monitor':
            result = quantum_encoder.start_monitoring()
            return jsonify(result)
            
        elif action == 'encode':
            message = request.form.get('message')
            try:
                result = quantum_encoder.encode_message(message)
                return jsonify(result)
            except Exception as e:
                return jsonify({'error': str(e)}), 400
                
        elif action == 'decode':
            states = request.form.get('states')
            try:
                result = quantum_decoder.decode_message(states)
                return jsonify(result)
            except Exception as e:
                return jsonify({'error': str(e)}), 400
                
    return render_template('quantum.html')

def log_action(action, media_filename=None, media_type=None):
    if current_user.is_authenticated:
        new_log = Log(user_id=current_user.id, action=action, media_filename=media_filename, media_type=media_type)
        db.session.add(new_log)
        db.session.commit()

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
