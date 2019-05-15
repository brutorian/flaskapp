from flask import Flask, redirect, render_template,  url_for, session, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, ValidationError
from wtforms.validators import DataRequired, Length, Email, EqualTo
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_login import UserMixin
from flask_login import login_user, current_user, logout_user, login_required
from flask_bcrypt import Bcrypt

app = Flask(__name__)
#config
import os
SECRET_KEY = os.urandom(32) #Create random secret key
app.config['SECRET_KEY'] = SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgres://tjrxdiwbosxtdo:ecadcd4c3fa96e24c8af4c249aac23a7342fa9fc5a720f63348e84d0c0f39058@ec2-54-228-252-67.eu-west-1.compute.amazonaws.com:5432/dakbjfjtc970u5'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy()#SQL
bcrypt = Bcrypt(app)#password security
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'#@login_required redirection

#Registration Form
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=15)])#least number of characters 8 most 30
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm password', validators=[DataRequired(), EqualTo('password')])#pssword same as confirm_password
    submit = SubmitField('Register')

    #validate email and username
    #validate username
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError

    #validate email
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError


#Login Form
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])  #required
    password = PasswordField('Password', validators=[DataRequired()])  #required
    remember = BooleanField('Remember me')
    submit = SubmitField('Login')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


#User db model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)#user id
    username = db.Column(db.String(20), unique=True, nullable=False)#User username is required
    email = db.Column(db.String(140), unique=True, nullable=False)
    password = db.Column(db.String(180), unique=True, nullable=False)


@app.route('/')
#home page
def index():
    return render_template("index.html")


@app.route('/about/')  #about page
@login_required
def about():
    return render_template('about.html')


@app.route('/policies/')  #policies page
@login_required
def policies():
    return render_template('policies.html')


@app.route('/education/')  #education page
@login_required
def education():
    return render_template('education.html')


@app.route('/signup/', methods=["GET", "POST"])  #signup page
def signup():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)  #collected data
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))  #redirect to login

    return render_template('signup.html', form=form)


@app.route('/login/', methods=["GET", "POST"])  #login page
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):  #hash_password data make secure
            login_user(user, remember=form.remember.data)
            return redirect(url_for('index'))
        else:

            return render_template('login.html', form=form)

    return render_template('login.html', form=form)


@app.route('/account/')
@login_required
def account():
    return render_template('account.html')


@app.route('/logout/')
def logout():
    logout_user()
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(DEBUG=True)
    db.init_app(app)
