"""
import os
from dotenv import load_dotenv, find_dotenv
from flask import Flask
import pages, posts, database, auth
from flask_login import UserMixin,login_user, LoginManager, login_required, logout_user, current_user

load_dotenv('WebsiteFiles.env')

def create_app():
    app = Flask(__name__)
    app.config.from_prefixed_env('WebsiteFiles.env')

    app.config['SECRET_KEY'] = 'flaskisfun'
    database.init_app(app)
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'login'
    
    app.register_blueprint(auth.bp)
    app.register_blueprint(pages.bp)
    app.register_blueprint(posts.bp)
    print(f"Current Environment: {os.getenv('ENVIRONMENT')}")
    print(f"Using Database: {app.config.get('DATABASE')}")
    return app
"""