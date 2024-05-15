from flask import Flask, render_template, request, redirect, session, flash, jsonify
from flask_bcrypt import Bcrypt
from pymongo import MongoClient
import datetime
import random
from bson import ObjectId

app = Flask(__name__)
bcrypt = Bcrypt(app)
client = MongoClient('localhost', 27017)
db = client['your_database_name']
app.secret_key = 'your_secret_key'  

def load_bad_ips():
    with open('nonauthrazip.txt', 'r') as file:  
        bad_ips = set(line.strip() for line in file if line.strip())
    return bad_ips

bad_ips = load_bad_ips()

def check_ip_blacklist(ip_address):
    return ip_address in bad_ips

def check_user_behavior(user_id, transaction_amount):
    average = db.payments.aggregate([
        {"$match": {"user_id": user_id}},
        {"$group": {"_id": None, "avgAmount": {"$avg": "$amount"}}}
    ]).next().get('avgAmount', 0)
    return transaction_amount > 2 * average  # Arbitrary factor of 2

def log_suspicious_activity(message, user_id):
    db.suspicious_activities.insert_one({"user_id": user_id, "message": message, "timestamp": datetime.datetime.now()})

def generate_random_ip():
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"

def generate_unique_ip():
    new_ip = generate_random_ip()
    while new_ip in bad_ips:
        new_ip = generate_random_ip()
    return new_ip

users = db.users
payments = db.payments

@app.route('/')
def home():
    if 'username' in session:
        return redirect('/dashboard')
    return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = db.users.find_one({'username': username})

        if user and bcrypt.check_password_hash(user['password'], password):
            session['username'] = user['username']
            session['user_id'] = str(user['_id'])
            return redirect('/dashboard')
        else:
            flash('Invalid username or password', 'error')
            return redirect('/login')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

@app.route('/create_account', methods=['POST', 'GET'])
def create_account():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        db.users.insert_one({'username': username, 'password': hashed_password})
        return redirect('/login')
    return render_template('create_account.html')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect('/login')
    payments = db.payments.find({'to_user': session['username'], 'status': 'pending'})
    return render_template('dashboard.html', username=session['username'], payments=payments)

@app.route('/suspended')
def suspended():
    return render_template('suspend.html')

@app.route('/request_payment', methods=['POST'])
def request_payment():
    ip_address = request.form['ip_address']
    if check_ip_blacklist(ip_address):
        flash('Transaction blocked due to risk associated with the IP address.', 'error')
        return redirect('/suspended')
    to_user = request.form['to_user']
    amount = float(request.form['amount'])
    db.payments.insert_one({'from_user': session['username'], 'to_user': to_user, 'amount': amount, 'status': 'pending', 'timestamp': datetime.datetime.now()})
    flash('Payment request sent.', 'success')
    return redirect('/dashboard')

@app.route('/complete_payment', methods=['POST'])
def complete_payment():
    payment_id = request.form['payment_id']
    payment = db.payments.find_one({"_id": ObjectId(payment_id)})

    ip_address = request.remote_addr
    if check_ip_blacklist(ip_address):
        flash('Transaction blocked due to risk associated with the IP address.', 'error')
        return redirect('/dashboard')

    db.payments.update_one({"_id": ObjectId(payment_id)}, {"$set": {"status": "completed"}})
    flash('Payment completed successfully!', 'success')
    return redirect('/dashboard')

@app.route('/generate_new_ip', methods=['GET'])
def generate_new_ip():
    new_ip = generate_unique_ip()
    return jsonify({"new_ip": new_ip})

if __name__ == '__main__':
    app.run(debug=True)
