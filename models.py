from flask_login import UserMixin
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import true
from werkzeug.security import generate_password_hash, check_password_hash

# Initialize the database
db = SQLAlchemy()

class User(db.Model, UserMixin):  # ✅ Inherit from UserMixin
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    is_admin = db.Column(db.Boolean, default=False)
    def __init__(self, username, email, password=None):
        self.username = username
        self.email = email
        if password:
            self.password_hash = generate_password_hash(password)

    def __repr__(self):
        return f'<User {self.username}>'

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(255), nullable=False)
    media_filename = db.Column(db.String(255))  # <-- Add this line
    media_type = db.Column(db.String(50))       # <-- Add this line
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='logs')
