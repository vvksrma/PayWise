from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import CheckConstraint, UniqueConstraint
import random
import string

db = SQLAlchemy()

def generate_account_number():
    """Generate a random 12-digit account number"""
    return ''.join(random.choices(string.digits, k=12))

def generate_customer_id():
    """Generate a random 6-character alphanumeric customer ID"""
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))

from datetime import date
from sqlalchemy import UniqueConstraint, CheckConstraint
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

def generate_account_number():
    # Your function to generate a unique account number
    pass

def generate_customer_id():
    # Your function to generate a unique customer ID
    pass

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    mobile_number = db.Column(db.String(15), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    balance = db.Column(db.Float, default=100000.0)
    account_number = db.Column(db.String(12), unique=True, nullable=False, default=generate_account_number)
    customer_id = db.Column(db.String(6), unique=True, nullable=False, default=generate_customer_id)
    dob = db.Column(db.Date, nullable=True)  # Date of Birth column
    profile_picture = db.Column(db.String(200), nullable=True)  # Profile Picture column
    
    transactions = db.relationship('Transaction', back_populates='user', lazy=True)

    __table_args__ = (
        UniqueConstraint('account_number', name='uq_account_number'),
        UniqueConstraint('customer_id', name='uq_customer_id'),
        UniqueConstraint('email', name='uq_user_email'),
        UniqueConstraint('mobile_number', name='uq_user_mobile_number'),
        CheckConstraint('balance >= 0', name='check_user_balance')
    )

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    type = db.Column(db.String(10), nullable=False)  # 'debit', 'credit'
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())
    remarks = db.Column(db.String(255))

    user = db.relationship('User', back_populates='transactions')

class Transfer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    debit_transaction_id = db.Column(db.Integer, db.ForeignKey('transaction.id'), nullable=False)
    credit_transaction_id = db.Column(db.Integer, db.ForeignKey('transaction.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())

    debit_transaction = db.relationship('Transaction', foreign_keys=[debit_transaction_id])
    credit_transaction = db.relationship('Transaction', foreign_keys=[credit_transaction_id])