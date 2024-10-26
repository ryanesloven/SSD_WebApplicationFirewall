import os
import re
from dotenv import load_dotenv, find_dotenv
from flask import Flask, request, abort
import flask_login
import flask
from database import get_db
import pages, posts, database, auth
from flask_login import UserMixin,login_user, LoginManager, login_required, logout_user, current_user



load_dotenv('WebsiteFiles.env')

class User():
    pass

def create_app():
    app = Flask(__name__)
    app.config.from_prefixed_env('WebsiteFiles.env')

    app.config['SECRET_KEY'] = 'flaskisfun'
    database.init_app(app)

    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'login'
    
    ##app.register_blueprint(auth.bp)
    app.register_blueprint(pages.bp)
    app.register_blueprint(posts.bp)
    print(f"Current Environment: {os.getenv('ENVIRONMENT')}")
    print(f"Using Database: {app.config.get('DATABASE')}")
    return app

app = create_app()

# Define a set of rules to filter out malicious requests
rules = {
    'sql_injection': re.compile(r'(union|select|insert|delete|update|drop|alter).*', re.IGNORECASE),
    'xss_attack': re.compile(r'(<script>|<iframe>).*', re.IGNORECASE),
    'path_traversal': re.compile(r'(\.\./|\.\.).*', re.IGNORECASE)
}

# Middleware to check each request against WAF rules
"""
@app.before_request
def check_request_for_attacks():
    for attack_type, pattern in rules.items():
        # If any of the rules match, we block the request
        if pattern.search(request.path) or pattern.search(request.query_string.decode()):
            abort(403, description=f'Request blocked by WAF: Detected {attack_type}')
"""

##code for login features
class User(flask_login.UserMixin):
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password = password
        self.authenticated = False    
    def is_active(self):
        return self.is_active()    
    def is_anonymous(self):
        return False    
    def is_authenticated(self):
        return self.authenticated    
    def is_active(self):
        return True    
    def get_id(self):
        return self.id

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def user_loader(username, _password):
    db = get_db()
    validUser = db.execute("SELECT COUNT(1) FROM userLogin WHERE (username) ==  username AND (_password) == password", (username, _password),)
    if (validUser != 1):
        return
    
    user = User()
    user.id = username
    return user

@login_manager.request_loader
def reqest_loader(request):
    db = get_db()
    username = request.form.get('username')
    password = request.form.get('password')
    validUser = db.execute("SELECT COUNT(1) FROM userLogin WHERE (username, _password) == (?, ?)", (username, password),)
    if (validUser != 1):
        return
    
    user = User()
    user.id = username
    return user


@app.route('/login', methods=['GET', 'POST'])
def login():
    db = get_db()
    if flask.request.method == 'GET':
        return '''
               <form action='login' method='POST'>
                <input type='text' name='email' id='email' placeholder='email'/>
                <input type='password' name='password' id='password' placeholder='password'/>
                <input type='submit' name='submit'/>
               </form>
               '''
    username = flask.request.form['username']
    password = flask.request.form['password']

    validUser = db.execute("SELECT COUNT(1) FROM userLogin WHERE (username, _password) == (?, ?)", (username, password),)
    if (validUser == 1):
        user = User()
        user.id = username
        flask_login.login_user(user)
        return flask.redirect(flask.url_for('protected'))
    return 'Bad Login'

@app.route('/logout')
def logout():
    flask_login.logout_user()
    return "Logged Out"

# Start the web application on port 5000
if __name__ == '__main__':
    app.run(port=5000)