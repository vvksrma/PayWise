import random
import string
from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from sqlalchemy import UniqueConstraint, CheckConstraint

db = SQLAlchemy()

def generate_account_number():
    """Generate a random 12-digit account number."""
    return ''.join(random.choices(string.digits, k=12))

def generate_customer_id():
    """Generate a random 6-character alphanumeric customer ID."""
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))

class User(db.Model, UserMixin):
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    mobile_number = db.Column(db.String(15), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    balance = db.Column(db.Float, default=100000.0)  # Set initial balance to ₹100,000
    account_number = db.Column(db.String(12), unique=True, nullable=False, default=generate_account_number)
    customer_id = db.Column(db.String(6), unique=True, nullable=False, default=generate_customer_id)

    __table_args__ = (
        UniqueConstraint('account_number', name='uq_account_number'),  # Name constraint for account_number
        UniqueConstraint('customer_id', name='uq_customer_id'),  # Name constraint for customer_id
        UniqueConstraint('email', name='uq_user_email'),
        UniqueConstraint('mobile_number', name='uq_user_mobile_number'),
        CheckConstraint('balance >= 0', name='check_user_balance')
    )

    def __repr__(self):
        return f"<User {self.username}>"

class Transaction(db.Model):
    __tablename__ = 'transaction'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    type = db.Column(db.String(50), nullable=False)  # 'debit' or 'credit'
    date = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))  # Updated for timezone-aware UTC datetime
    user = db.relationship('User', backref=db.backref('transactions', lazy=True))

    def __repr__(self):
        return f"<Transaction {self.type.capitalize()} {self.amount}>"
