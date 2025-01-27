import random
import string
import os
import google.generativeai as genai
from google.generativeai.types import generation_types
from dotenv import load_dotenv
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
from sqlalchemy import CheckConstraint, UniqueConstraint
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature

# Load environment variables
load_dotenv()

# Configure Google Generative AI
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))

# Function to load Gemini Pro model and get response
model = genai.GenerativeModel("gemini-pro")

def get_financial_response(question):
    # Contextual prompt to ensure the model responds as a financial expert
    prompt = f"You are a financial expert. Answer the following question: {question}"
    try:
        # Create a new chat session for each request
        chat = model.start_chat(history=[])
        response = chat.send_message(prompt)
        return response.text  # Adjust this line according to the actual response structure
    except generation_types.StopCandidateException as e:
        # Log the error and return a user-friendly message
        print(f"StopCandidateException Error: {e}")
        return "I'm sorry, but I couldn't generate a response to your question. Please try again."
    except Exception as e:
        # Catch any other exceptions and log them
        print(f"Unexpected Error: {e}")
        return "An unexpected error occurred. Please try again later."

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///bank.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)  # Ensure upload folder exists
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True

db = SQLAlchemy(app)
migrate = Migrate(app, db)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Serializer for generating and validating tokens
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

def generate_account_number():
    """Generate a random 12-digit account number"""
    return ''.join(random.choices(string.digits, k=12))

def generate_customer_id():
    """Generate a random 6-character alphanumeric customer ID"""
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    mobile_number = db.Column(db.String(15), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    balance = db.Column(db.Float, default=100000.0)
    account_number = db.Column(db.String(12), unique=True, nullable=False, default=generate_account_number)
    customer_id = db.Column(db.String(6), unique=True, nullable=False, default=generate_customer_id)
    dob = db.Column(db.Date, nullable=True)
    profile_picture = db.Column(db.String(200), nullable=True)
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
    type = db.Column(db.String(10), nullable=False)
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

class MoneyRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(10), default='pending')  # 'pending', 'approved', 'declined'
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())
    remarks = db.Column(db.String(255))
    
    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_requests')
    recipient = db.relationship('User', foreign_keys=[recipient_id], backref='received_requests')

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():  
    return render_template('contact.html')

@app.route('/privacy')  
def privacy():  
    return render_template('privacy.html')

@app.route('/terms')
def terms():  
    return render_template('terms.html')   

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            profile_picture_file = request.files.get('profile_picture')
            full_name = request.form.get('full_name')
            username = request.form.get('username')
            dob = request.form.get('dob')
            email = request.form.get('email')
            mobile_number = request.form.get('mobile_number')
            password = request.form.get('password')

            if profile_picture_file and profile_picture_file.filename:
                filename = secure_filename(profile_picture_file.filename)
                profile_picture_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                profile_picture_file.save(profile_picture_path)
                profile_picture = filename
            else:
                profile_picture = None

            dob_parsed = datetime.strptime(dob, '%Y-%m-%d').date() if dob else None

            if User.query.filter_by(username=username).first():
                flash('Username already exists. Please choose another one.', 'error')
                return redirect(url_for('register'))

            if User.query.filter_by(email=email).first():
                flash('Email already exists. Please choose another one.', 'error')
                return redirect(url_for('register'))

            if User.query.filter_by(mobile_number=mobile_number).first():
                flash('Mobile number already exists. Please choose another one.', 'error')
                return redirect(url_for('register'))

            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            new_user = User(
                profile_picture=profile_picture,
                full_name=full_name,
                username=username,
                dob=dob_parsed,
                email=email,
                mobile_number=mobile_number,
                password=hashed_password
            )
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))

        except Exception as e:
            flash(f'Error during registration: {str(e)}', 'error')
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'error')

    return render_template('login.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            token = s.dumps(email, salt='password-reset')
            flash(f'Reset token (for demo purposes): {token}', 'info')
            flash('An email with instructions to reset your password has been sent to you.', 'info')
        else:
            flash('No account with that email address exists.', 'error')
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset', max_age=3600)
    except SignatureExpired:
        flash('The reset link is no longer valid.', 'error')
        return redirect(url_for('forgot_password'))
    except BadTimeSignature:
        flash('Invalid reset token.', 'error')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user:
            user.password = generate_password_hash(password, method='pbkdf2:sha256')
            db.session.commit()
            flash('Your password has been updated!', 'success')
            return redirect(url_for('login'))
        else:
            flash('An error occurred. Please try again.', 'error')

    return render_template('reset_password.html')

@app.route('/forgot_username', methods=['GET', 'POST'])
def forgot_username():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            flash(f'Your username (for demo purposes): {user.username}', 'info')
            flash('An email with your username has been sent to you.', 'info')
        else:
            flash('No account with that email address exists.', 'error')
    return render_template('forgot_username.html')

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    if request.method == 'POST':
        try:
            if 'withdraw' in request.form:
                amount = float(request.form.get('amount'))
                remarks = request.form.get('remarks')
                if current_user.balance < amount:
                    flash('Insufficient funds.', 'error')
                else:
                    current_user.balance -= amount
                    transaction = Transaction(user_id=current_user.id, amount=amount, type='debit', remarks=remarks)
                    db.session.add(transaction)
                    db.session.commit()
                    flash(f'Withdrew ₹{amount} successfully.', 'success')

            elif 'transfer' in request.form:
                recipient_username = request.form.get('recipient')
                amount = float(request.form.get('amount'))
                remarks = request.form.get('remarks')
                recipient = User.query.filter_by(username=recipient_username).first()
                if not recipient:
                    flash('Recipient does not exist.', 'error')
                elif current_user.balance < amount:
                    flash('Insufficient funds.', 'error')
                else:
                    current_user.balance -= amount
                    recipient.balance += amount
                    debit_transaction = Transaction(user_id=current_user.id, amount=amount, type='debit', remarks=remarks)
                    credit_transaction = Transaction(user_id=recipient.id, amount=amount, type='credit', remarks=remarks)
                    db.session.add(debit_transaction)
                    db.session.add(credit_transaction)
                    db.session.commit()
                    transfer = Transfer(debit_transaction_id=debit_transaction.id, credit_transaction_id=credit_transaction.id)
                    db.session.add(transfer)
                    db.session.commit()
                    flash(f'Transferred ₹{amount} to {recipient_username}.', 'success')

            elif 'request_money' in request.form:
                recipient_username = request.form.get('recipient')
                amount = float(request.form.get('amount'))
                remarks = request.form.get('remarks')
                recipient = User.query.filter_by(username=recipient_username).first()
                if not recipient:
                    flash('Recipient does not exist.', 'error')
                else:
                    money_request = MoneyRequest(sender_id=current_user.id, recipient_id=recipient.id, amount=amount, remarks=remarks)
                    db.session.add(money_request)
                    db.session.commit()
                    flash(f'Requested ₹{amount} from {recipient_username}.', 'info')

        except Exception as e:
            db.session.rollback()
            flash(f'Error during operation: {str(e)}', 'error')

    transactions = Transaction.query.filter_by(user_id=current_user.id).order_by(Transaction.timestamp.desc()).all()
    money_requests = MoneyRequest.query.filter_by(recipient_id=current_user.id).all()

    # Data for the interactive graph
    dates = [transaction.timestamp.strftime('%Y-%m-%d') for transaction in transactions]
    balances = []
    balance = 100000.0  # Initial balance, you can replace it with the actual initial balance
    for transaction in transactions:
        if transaction.type == 'credit':
            balance += transaction.amount
        else:
            balance -= transaction.amount
        balances.append(balance)

    return render_template('dashboard.html', user=current_user, transactions=transactions, money_requests=money_requests, dates=dates, balances=balances)

@app.route('/balance_graph')
@login_required
def balance_graph():
    balance_graph()

@app.route('/approve_request/<int:request_id>', methods=['POST'])
@login_required
def approve_request(request_id):
    money_request = MoneyRequest.query.get_or_404(request_id)

    if money_request.recipient != current_user:
        return jsonify({'success': False, 'message': 'Unauthorized request.'}), 403

    if money_request.status != 'pending':
        return jsonify({'success': False, 'message': 'Request not pending.'}), 400

    if current_user.balance < money_request.amount:
        return jsonify({'success': False, 'message': 'Insufficient funds.'}), 400

    sender = User.query.get(money_request.sender_id)
    if not sender:
        return jsonify({'success': False, 'message': 'Sender not found.'}), 400

    try:
        # Update balances
        current_user.balance -= money_request.amount
        sender.balance += money_request.amount

        # Update request status
        money_request.status = 'approved'

        # Create transactions
        debit_transaction = Transaction(user_id=current_user.id, amount=money_request.amount, type='debit', remarks=money_request.remarks)
        credit_transaction = Transaction(user_id=money_request.sender_id, amount=money_request.amount, type='credit', remarks=money_request.remarks)

        db.session.add_all([money_request, debit_transaction, credit_transaction])
        db.session.flush()  # Ensure IDs are assigned

        # Link transactions in Transfer
        transfer = Transfer(debit_transaction_id=debit_transaction.id, credit_transaction_id=credit_transaction.id)
        db.session.add(transfer)

        # Commit the session
        db.session.commit()
        return jsonify({'success': True, 'message': 'Request approved.'})

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error approving request: {e}")
        return jsonify({'success': False, 'message': 'An internal error occurred.'}), 500


@app.route('/decline_request/<int:request_id>', methods=['POST'])
@login_required
def decline_request(request_id):
    money_request = MoneyRequest.query.get_or_404(request_id)
    if money_request.recipient != current_user:
        return jsonify({'success': False, 'message': 'Unauthorized request.'}), 403

    if money_request.status == 'pending':
        money_request.status = 'declined'
        db.session.commit()
        flash('Request declined.', 'warning')
        return jsonify({'success': True, 'message': 'Request declined.'})

    return jsonify({'success': False, 'message': 'Request not pending.'}), 400

@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        email = request.form.get('email')
        mobile_number = request.form.get('mobile_number')
        profile_picture_file = request.files.get('profile_picture')

        if User.query.filter(User.email == email, User.id != current_user.id).first():
            flash('Email already exists. Please choose another one.', 'error')
            return redirect(url_for('edit_profile'))

        if User.query.filter(User.mobile_number == mobile_number, User.id != current_user.id).first():
            flash('Mobile number already exists. Please choose another one.', 'error')
            return redirect(url_for('edit_profile'))

        current_user.email = email
        current_user.mobile_number = mobile_number
        current_user.profile_picture = profile_picture_file.filename if profile_picture_file else current_user.profile_picture
        db.session.commit()
        flash('Profile updated successfully.', 'success')
        return redirect(url_for('dashboard'))

    return render_template('edit_profile.html', user=current_user)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))

# New route to serve the chat page
@app.route('/chat')
def chat():
    return render_template('chat.html')

# New route to handle chatbot responses
@app.route('/get_response', methods=['POST'])
def chat_response():
    data = request.get_json()
    user_input = data.get('message')
    if user_input:
        response = get_financial_response(user_input)
        return jsonify({"response": response})
    return jsonify({"response": "No input provided"}), 400

@app.route('/filter_transactions')
@login_required
def filter_transactions():
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    transactions = Transaction.query.filter(Transaction.user_id == current_user.id, Transaction.timestamp >= start_date, Transaction.timestamp <= end_date).order_by(Transaction.timestamp.desc()).all()
    response = [{'type': t.type, 'amount': t.amount, 'timestamp': t.timestamp.strftime('%Y-%m-%d %H:%M:%S'), 'remarks': t.remarks} for t in transactions]
    return jsonify(transactions=response)

@app.route('/filter_requests')
@login_required
def filter_requests():
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    money_requests = MoneyRequest.query.filter(MoneyRequest.recipient_id == current_user.id, MoneyRequest.timestamp >= start_date, MoneyRequest.timestamp <= end_date).order_by(MoneyRequest.timestamp.desc()).all()
    response = [{'sender': r.sender.username, 'amount': r.amount, 'timestamp': r.timestamp.strftime('%Y-%m-%d %H:%M:%S'), 'status': r.status, 'remarks': r.remarks, 'id': r.id} for r in money_requests]
    return jsonify(requests=response)

@app.route('/load_more_transactions')
@login_required
def load_more_transactions():
    offset = int(request.args.get('offset'))
    transactions = Transaction.query.filter_by(user_id=current_user.id).order_by(Transaction.timestamp.desc()).offset(offset).limit(8).all()
    response = [{'type': t.type, 'amount': t.amount, 'timestamp': t.timestamp.strftime('%Y-%m-%d %H:%M:%S'), 'remarks': t.remarks} for t in transactions]
    return jsonify(transactions=response)

@app.route('/load_more_requests')
@login_required
def load_more_requests():
    offset = int(request.args.get('offset'))
    money_requests = MoneyRequest.query.filter_by(recipient_id=current_user.id).order_by(MoneyRequest.timestamp.desc()).offset(offset).limit(8).all()
    response = [{'sender': r.sender.username, 'amount': r.amount, 'timestamp': r.timestamp.strftime('%Y-%m-%d %H:%M:%S'), 'status': r.status, 'remarks': r.remarks, 'id': r.id} for r in money_requests]
    return jsonify(requests=response)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)