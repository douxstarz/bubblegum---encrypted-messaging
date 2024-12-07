from flask import Flask, session, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length
import bcrypt
import os
from config import Config
from flask_mail import Mail, Message
import random
from datetime import datetime, timedelta

app = Flask(__name__)
app.config.from_object(Config)

class User(UserMixin):
    def __init__(self, id, username, email, password):
        self.id=id
        self.username=username
        self.password=password
        self.email=email

users = {}
otp_storage = {}

def hash_password(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt)

def check_password(pass_entered, pass_hashed):
    return bcrypt.checkpw(pass_entered.encode('utf-8'),pass_hashed)

class RegistrationForm(FlaskForm):
    username = StringField('username', validators=[DataRequired(), Length(min=3, max=15)])
    password = PasswordField('password', validators=[DataRequired(), Length(min=6)])
    email = StringField('email', validators=[DataRequired(), Email()])
    submit = SubmitField('register')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data
        print(f"Username: {username}, Email: {email}, Password: {password}")

        hashed_pass = hash_password(password)
        
        new_user = User(id=len(users)+1, username=username, email=email, password=hashed_pass)
        users[new_user.id] = new_user

        flash('registration success!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html',form=form)

class LoginForm(FlaskForm):
    username = StringField('username', validators=[DataRequired()])
    password = PasswordField('password', validators=[DataRequired()])
    submit = SubmitField('login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user = next((u for u in users.values() if u.username == username), None)
        if user and bcrypt.checkpw(password.encode('utf-8'), user.password):
            session['user_id']=user.id
            session['user_email']=user.email
            otp_generate(user.email)
            flash('OTP sent to email - please verify', 'info')
            return redirect(url_for('verify_otp'))
        
        else:
            flash('invalid username or password', "unsuccessful")
    
    return render_template('login.html', form=form)

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return users.get(int(user_id))

mail=Mail(app)

def otp_generate(email):
    otp = random.randint(100000, 999999)
    expiry_time = datetime.now() + timedelta(minutes=5)
    otp_storage[email] = {'otp': otp, 'expires': expiry_time}

    msg = Message('your otp code', sender='doxxuz@gmail.com', recipients=[email])
    msg.body = f'your OTP is {otp} and is valid for 5 minutes'
    mail.send(msg)

    return otp

@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/logout')
def logout():
    
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        entered_otp = request.form.get('otp')
        user_email = session.get('user_email')

        if not user_email:
            flash('Session expired. Please log in again.', 'danger')
            return redirect(url_for('login'))

        otp_data = otp_storage.get(user_email)
        if not otp_data:
            flash('No OTP found for this email. Please log in again.', 'danger')
            return redirect(url_for('login'))

        otp = otp_data['otp']
        expiry_time = otp_data['expires']
        if datetime.now() > expiry_time:
            flash('OTP expired. Please request a new one.', 'danger')
        elif entered_otp == str(otp):
            flash('You are now logged in!', 'success')
            session.pop('user_email', None)
            session.pop('user_id', None)
            return redirect(url_for('home'))
        else:
            flash('Invalid OTP, please try again.', 'danger')

    return render_template('verification.html')
     
