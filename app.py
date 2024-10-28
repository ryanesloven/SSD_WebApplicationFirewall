import os
from dotenv import load_dotenv, find_dotenv
from flask import Flask, request, abort, flash, redirect, url_for, render_template, get_flashed_messages
import flask_login
import datetime
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
import pages
from flask_login import UserMixin,login_user, LoginManager, login_required, logout_user, current_user
from sqlalchemy import create_engine, TIMESTAMP
from flask_sqlalchemy import SQLAlchemy

def create_app():
    app = Flask(__name__)
    app.config.from_prefixed_env('WebsiteFiles.env')
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///webDatabase.db'
    app.config['SECRET_KEY'] = 'flaskisfun'

    app.register_blueprint(pages.bp)
    print(f"Current Environment: {os.getenv('ENVIRONMENT')}")
    print(f"Using Database: {app.config.get('DATABASE')}")
    return app

app = create_app()
db = SQLAlchemy(app)

##code for login features
class Posts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.String(100), nullable=False)
    message = db.Column(db.String(500), nullable=False)
    created = db.Column(TIMESTAMP, default=datetime.datetime.now)

class SignupForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class Users(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)

##sets up database
with app.app_context():
    db.create_all()

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def user_loader(user_id):
    return Users.query.get(user_id)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        user = Users.query.filter_by(username=request.form.get("username")).first()
        if user is not None and user.password == request.form.get("password"):
            login_user(user)
            return redirect(url_for("pages.home"))
        else:
            flash("Invalid login information, please try again.")
    return render_template("pages/login.html")
    

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if request.method == "POST":
        user = Users.query.filter_by(username=request.form.get("username")).first()
        if user is not None:
            flash('This username is already associated with an account.')
        else:
            user = Users(username=request.form.get("username"), password=request.form.get("password"))
            db.session.add(user)
            db.session.commit()
            flash('Successfully signed up! You can now log in.')
            get_flashed_messages(with_categories=True)
            return redirect(url_for('login'))

    return render_template("pages/signup.html", form=form)

@app.route('/logout')
def logout():
    flask_login.logout_user()
    return "Logged Out"

@app.route('/protected')
@flask_login.login_required
def protected():
    return 'Logged in as: ' + flask_login.current_user.id

@app.route("/create", methods=("GET", "POST"))
def create():
    if request.method == "POST":
        flash("Your Name: "+current_user.username)
        post = Posts(author=current_user.username, message=request.form.get("message"))
        db.session.add(post)
        db.session.commit()
        get_flashed_messages(with_categories=True)
        return redirect(url_for("posts"))
    return render_template("posts/create.html")

@app.route("/posts")
def posts():
    posts = Posts.query.all()
    return render_template("posts/posts.html", posts=posts)

# Start the web application on port 5000
if __name__ == '__main__':
    app.run(port=5000)