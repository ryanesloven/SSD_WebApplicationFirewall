from flask import (
    Blueprint, 
    render_template,
    redirect,
    request,
    url_for,
    abort,
    request)
import re
from app import get_db

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

