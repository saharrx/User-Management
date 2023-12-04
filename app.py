import os
from flask import Flask, render_template, flash, url_for, redirect, session, request, make_response, jsonify
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv
import psycopg2

from datetime import datetime, timedelta
from functools import wraps
from flask_jwt_extended import create_access_token
from flask_jwt_extended import current_user
from flask_jwt_extended import JWTManager


app = Flask(__name__)

load_dotenv()


app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('database_uri')
print(app.config['SQLALCHEMY_DATABASE_URI'])
app.config['SECRET_KEY'] = os.getenv('SECERET_KEY')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
migrate = Migrate(app, db)
app.config['RBAC_USE_WHITE'] = True


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


def token_required(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        token = request.args.get('token')
        if not token:
            return print('token is missing!!!')
        try:
            payload = jwt.decode(token, app.config['SECERET_KEY'])
        except:
            return print('Invalid token!!!!')
    return decorated


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def load_all_users():
    return User.query.all()


@jwt.user_identity_loader
def user_identity_lookup(user):
    return user.id


@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return User.query.filter_by(id=identity).one_or_none()


class User(db.Model, UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

    def __init__(self, username, password):
        self.username = username
        self.password = password

    def __repr__(self):
        return '<User %r' % self.username


class SignUpForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Username"})

    password1 = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Password"})

    password2 = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Repeat Password"})

    submit = SubmitField("Sign Up")

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            return False
        else:
            return True


class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField("Login")


@app.route('/')
def welcome():
    return render_template('welcome.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user, remember=True)
                flash('logged in successfully', category='success')
                access_token = create_access_token(identity=user)
                print(access_token, '  logged in successfully')
                return redirect(url_for('home', username=user.username))
            else:
                flash('Incorrect password! Try again', category='error')
        else:
            flash("User doesn't exist", category='error')

    return render_template('login.html', form=form)


@app.route('/home', methods=['GET'])
def home():
    username = request.args.get('username')
    return render_template('home.html', username=username)


@ app.route('/logout')
@ login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@ app.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    form = SignUpForm()
    if form.validate_on_submit():
        if form.password1.data == form.password2.data:
            hashed_password = bcrypt.generate_password_hash(
                form.password1.data).decode('utf-8')
            new_user = User(username=form.username.data,
                            password=hashed_password)
            print(new_user)
            db.session.add(new_user)
            db.session.commit()
            flash('user successfully created!', category='success')
            return redirect(url_for('login'))
        else:
            flash('passwords don\'t match.', category='error')

    return render_template('signup.html', form=form)


@ app.route('/remove_user', methods=['GET', 'POST'])
@ login_required
# @ token_required
def remove_user():
    if request.method == 'POST':
        selected_username = request.form.get('username')
        selected_user = User.query.filter_by(
            username=selected_username).first()
        if selected_user:
            User.query.filter_by(username=selected_username).delete()
            db.session.commit()
            flash('user DELETED !', category='success')
            return redirect(url_for('get_user'))
        else:
            flash("user doesn't exist", category='error')

    return render_template('removeuser.html', user=current_user)


@ app.route('/get_user', methods=['GET', 'POST'])
@ login_required
# @ token_required
def get_user():
    data = []
    all_users = load_all_users()
    for eachuser in all_users:
        data.append((eachuser.id, eachuser.username))

    if request.method == 'POST' and request.form['submit_button'] == 'search':
        data = []
        selected_username = request.form.get('username')
        user = User.query.filter_by(username=selected_username).first()
        if user:
            print(user)
            data.append((user.id, user.username))
        else:
            flash('user doesn\'t exist :(', category='error')

    print(data)
    return render_template('getuser.html', user=current_user, data=data)


if __name__ == '__main__':
    app.run(debug=True)
