from flask import (
    Blueprint, 
    render_template,
    redirect,
    request,
    url_for,
    abort,
    request)
import re
from WebsiteFiles.database import get_db

bp = Blueprint("posts", __name__)

rules = {
    'sql_injection': re.compile(r'(union|select|insert|delete|update|drop|alter).*', re.IGNORECASE),
    'xss_attack': re.compile(r'(<script>|<iframe>).*', re.IGNORECASE),
    'path_traversal': re.compile(r'(\.\./|\.\.).*', re.IGNORECASE)
}

# Middleware to check each request against WAF rules
@bp.before_request
def check_request_for_attacks():
    for attack_type, pattern in rules.items():
        # If any of the rules match, we block the request
        if pattern.search(request.path) or pattern.search(request.query_string.decode()):
            abort(403, description=f'Request blocked by WAF: Detected {attack_type}')

@bp.route("/create", methods=("GET", "POST"))
def create():
    if request.method == "POST":
        author = request.form["author"] or "Anonymous"
        message = request.form["message"]

        if message:
            db = get_db()
            db.execute("INSERT INTO post (author, message) VALUES (?, ?)", (author, message),)
            db.commit()
            return redirect(url_for("posts.posts"))
    return render_template("posts/create.html")

@bp.route("/posts")
def posts():
    db = get_db()
    posts = db.execute("SELECT author, message, created FROM post ORDER BY created DESC").fetchall()
    return render_template("posts/posts.html", posts=posts)