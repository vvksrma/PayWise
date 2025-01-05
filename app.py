import random
import string
import matplotlib
matplotlib.use('Agg')  # Use Agg backend for Matplotlib
import matplotlib.pyplot as plt
import io
import base64
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
from sqlalchemy import CheckConstraint, UniqueConstraint
from sqlalchemy.orm import Session
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///bank.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

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
    with db.session() as session:
        return session.get(User, int(user_id))

def generate_transaction_trend_graph(user_id):
    # Fetch transactions for the user from the database
    transactions = Transaction.query.filter_by(user_id=user_id).order_by(Transaction.timestamp).all()

    # Data to be plotted
    dates = []
    balances = []
    balance = 0  # Initial balance

    for transaction in transactions:
        dates.append(transaction.timestamp.strftime('%Y-%m-%d'))
        if transaction.type == 'credit':
            balance += transaction.amount
        else:  # debit
            balance -= transaction.amount
        balances.append(balance)

    # Create the plot
    plt.figure(figsize=(10, 6))
    
    # Plot the balance over time with markers
    plt.plot(dates, balances, label='Balance over time', color='blue', marker='o')

    # Adding annotations to each point
    for i, txt in enumerate(balances):
        plt.annotate(f'{txt:.2f}', (dates[i], balances[i]), textcoords="offset points", xytext=(0,10), ha='center')

    plt.xticks(rotation=45)
    plt.xlabel('Date', fontsize=14)
    plt.ylabel('Balance (₹)', fontsize=14)
    plt.title('Your Account Balance Over Time', fontsize=16)
    plt.grid(True)
    plt.legend()

    # Convert the plot to a PNG image and encode it to base64
    img = io.BytesIO()
    plt.savefig(img, format='png')
    img.seek(0)
    img_b64 = base64.b64encode(img.getvalue()).decode('utf-8')
    plt.close()  # Close the plot to free up resources

    return img_b64

class User(db.Model, UserMixin):
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
        UniqueConstraint('email', name='uq_user_email'),
        UniqueConstraint('mobile_number', name='uq_user_mobile_number'),
        CheckConstraint('balance >= 0', name='check_user_balance')
    )

    def __repr__(self):
        return f'<User {self.username}>'


class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    type = db.Column(db.String(10), nullable=False)  # 'debit', 'credit'
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())
    remarks = db.Column(db.String(255))

    user = db.relationship('User', back_populates='transactions')


User.transactions = db.relationship('Transaction', back_populates='user', lazy='dynamic')


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


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        full_name = request.form.get('full_name')
        username = request.form.get('username')
        email = request.form.get('email')
        mobile_number = request.form.get('mobile_number')
        password = request.form.get('password')

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
            full_name=full_name,
            username=username,
            email=email,
            mobile_number=mobile_number,
            password=hashed_password
        )
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))

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
            # You would normally send the email here, but for simplicity, we'll just flash the token
            flash(f'Reset token (for demo purposes): {token}', 'info')
            # send_email(user.email, 'Password Reset Request', 'reset_password', user=user, token=token)
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
        if 'withdraw' in request.form:
            amount = float(request.form.get('amount'))
            remarks = request.form.get('remarks')
            if current_user.balance < amount:
                flash('Insufficient funds.', 'error')
            else:
                current_user.balance -= amount
                db.session.add(Transaction(user_id=current_user.id, amount=amount, type='debit', remarks=remarks))
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
                db.session.add(Transaction(user_id=current_user.id, amount=amount, type='debit', remarks=remarks))
                db.session.add(Transaction(user_id=recipient.id, amount=amount, type='credit', remarks=remarks))
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

    transactions = Transaction.query.filter_by(user_id=current_user.id).all()
    money_requests = MoneyRequest.query.filter_by(recipient_id=current_user.id).all()

    # Data for the interactive graph
    dates = [transaction.timestamp.strftime('%Y-%m-%d') for transaction in transactions]
    balances = []
    balance = 0
    for transaction in transactions:
        if transaction.type == 'credit':
            balance += transaction.amount
        else:
            balance -= transaction.amount
        balances.append(balance)

    return render_template('dashboard.html', user=current_user, transactions=transactions, money_requests=money_requests, dates=dates, balances=balances)

@app.route('/balance_graph', methods=['GET'])
@login_required
def balance_graph():
    # Generate the balance graph for the logged-in user
    img_b64 = generate_transaction_trend_graph(current_user.id)
    return render_template('balance_graph.html', img_data=img_b64)

@app.route('/approve_request/<int:request_id>', methods=['POST'])
@login_required
def approve_request(request_id):
    money_request = MoneyRequest.query.get_or_404(request_id)
    if money_request.recipient != current_user:
        return jsonify({'success': False, 'message': 'Unauthorized request.'}), 403

    if money_request.status == 'pending':
        if current_user.balance < money_request.amount:
            return jsonify({'success': False, 'message': 'Insufficient funds to approve the request.'}), 400
        else:
            current_user.balance -= money_request.amount
            money_request.sender.balance += money_request.amount
            money_request.status = 'approved'
            db.session.add(Transaction(user_id=current_user.id, amount=money_request.amount, type='debit', remarks=money_request.remarks))
            db.session.add(Transaction(user_id=money_request.sender.id, amount=money_request.amount, type='credit', remarks=money_request.remarks))
            db.session.commit()
            flash('Request approved.', 'success')
            return jsonify({'success': True, 'message': 'Request approved.'})

    return jsonify({'success': False, 'message': 'Request not pending.'}), 400


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

        if User.query.filter(User.email == email, User.id != current_user.id).first():
            flash('Email already exists. Please choose another one.', 'error')
            return redirect(url_for('edit_profile'))

        if User.query.filter(User.mobile_number == mobile_number, User.id != current_user.id).first():
            flash('Mobile number already exists. Please choose another one.', 'error')
            return redirect(url_for('edit_profile'))

        current_user.email = email
        current_user.mobile_number = mobile_number
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

@app.route('/chat')
@login_required
def chat():
    return render_template('chat.html')

@app.route('/filter_transactions')
@login_required
def filter_transactions():
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    filtered_transactions = Transaction.query.filter(Transaction.user_id == current_user.id, Transaction.timestamp >= start_date, Transaction.timestamp <= end_date).all()
    transactions = [{'type': t.type, 'amount': t.amount, 'timestamp': t.timestamp.strftime('%Y-%m-%d %H:%M:%S'), 'remarks': t.remarks} for t in filtered_transactions]
    return jsonify({'transactions': transactions})

@app.route('/filter_requests')
@login_required
def filter_requests():
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    filtered_requests = MoneyRequest.query.filter(MoneyRequest.recipient_id == current_user.id, MoneyRequest.timestamp >= start_date, MoneyRequest.timestamp <= end_date).all()
    requests = [{'id': r.id, 'sender': {'username': r.sender.username}, 'amount': r.amount, 'timestamp': r.timestamp.strftime('%Y-%m-%d %H:%M:%S'), 'status': r.status, 'remarks': r.remarks} for r in filtered_requests]
    return jsonify({'requests': requests})

@app.route('/load_more_transactions')
@login_required
def load_more_transactions():
    offset = int(request.args.get('offset'))
    more_transactions = Transaction.query.filter_by(user_id=current_user.id).offset(offset).limit(8).all()
    transactions = [{'type': t.type, 'amount': t.amount, 'timestamp': t.timestamp.strftime('%Y-%m-%d %H:%M:%S'), 'remarks': t.remarks} for t in more_transactions]
    return jsonify({'transactions': transactions})

@app.route('/load_more_requests')
@login_required
def load_more_requests():
    offset = int(request.args.get('offset'))
    more_requests = MoneyRequest.query.filter_by(recipient_id=current_user.id).offset(offset).limit(8).all()
    requests = [{'id': r.id, 'sender': {'username': r.sender.username}, 'amount': r.amount, 'timestamp': r.timestamp.strftime('%Y-%m-%d %H:%M:%S'), 'status': r.status, 'remarks': r.remarks} for r in more_requests]
    return jsonify({'requests': requests})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)