from flask import Flask, session, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, login_required, logout_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length
import bcrypt
import random
from datetime import datetime, timedelta
from app_setup import app, db, mail, login_manager
from flask_mail import Mail, Message


with app.app_context():
    db.create_all()

## models

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class OTP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_email = db.Column(db.String(100), nullable=False)
    otp = db.Column(db.String(4), nullable=False)
    expires = db.Column(db.DateTime, nullable=False)

users = {}
otp_storage = {}
otp_request_limits = {}

## util

def hash_password(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt)
    

def check_password(pass_entered, pass_hashed):
    return bcrypt.checkpw(pass_entered.encode('utf-8'),pass_hashed)

## forms

class RegistrationForm(FlaskForm):
    username = StringField('username', validators=[DataRequired(), Length(min=3, max=15)])
    password = PasswordField('password', validators=[DataRequired(), Length(min=4)])
    email = StringField('email', validators=[DataRequired(), Email()])
    submit = SubmitField('register')


class LoginForm(FlaskForm):
    username = StringField('username', validators=[DataRequired()])
    password = PasswordField('password', validators=[DataRequired()])
    stay_logged_in = SubmitField('stay_logged_in')
    submit = SubmitField('login')

## app.route

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data
        
        if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
            flash('username or email already exists!', 'unsuccessful')
            return redirect(url_for('register'))

        hashed_pass = hash_password(password)
        new_user = User(username=username, email=email, password=hashed_pass)
        db.session.add(new_user)
        db.session.commit()
        flash('registration successful!', 'success')
        return redirect(url_for('login'))

    return render_template('register.html',form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user = User.query.filter_by(username=username).first()
        if user and check_password(password, user.password):
            login_user(user)
            session['user_email']=user.email
            
            otp_generate(user.email)
            flash('OTP sent to email', 'info')
            return redirect(url_for('verify_otp'))

        
        flash('invalid username or password', "unsuccessful")
    
    return render_template('login.html', form=form)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def otp_generate(email):
    otp = f"{random.randint(1000,9999):04}"
    expiry_time = datetime.now() + timedelta(minutes=5)
    
    existing_otp = OTP.query.filter_by(user_email=email).first()
    if existing_otp:
        db.session.delete(existing_otp)
        db.session.commit()

    new_otp = OTP(user_email=email, otp=str(otp), expires=expiry_time)
    db.session.add(new_otp)
    db.session.commit()

    msg = Message('your otp code', sender='doxxuz@gmail.com', recipients=[email])
    msg.body = f'your otp is {otp} and is valid for 5 minutes'
    try:
        mail.send(msg)
    except Exception as e:
        flash("failed to send otp. please try again", "unsuccessful")
        print(f"email error: {e}")

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        entered_otp = request.form.get('otp')
        user_email = session.get('user_email')

        if not user_email:
            flash('session expired. please log in again.', 'unsuccessful')
            return redirect(url_for('login'))


        otp_record = OTP.query.filter_by(user_email=user_email).first()
        if not otp_record:
            flash('No OTP found for this email. Please log in again.', 'danger')
            return redirect(url_for('login'))

        if datetime.now() > otp_record.expires:
            flash('OTP expired. please request a new one', 'unsuccessful')
        elif otp_record.otp == entered_otp:
            flash('logged in!', 'success')
            db.session.delete(otp_record)
            db.session.commit()
            return redirect(url_for('home'))
        else:
            flash('Invalid OTP, please try again.', 'danger')

    return render_template('verification.html')

@app.route('/home')
@login_required
def home():
    return render_template('home.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)