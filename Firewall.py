import re
from flask import Flask, request, abort

app = Flask(__name__)

# Define a set of rules to filter out malicious requests
rules = {
    'sql_injection': re.compile(r'(union|select|insert|delete|update|drop|alter).*', re.IGNORECASE),
    'xss_attack': re.compile(r'(<script>|<iframe>).*', re.IGNORECASE),
    'path_traversal': re.compile(r'(\.\./|\.\.).*', re.IGNORECASE)
}

# Middleware to check each request against WAF rules
@app.before_request
def check_request_for_attacks():
    for attack_type, pattern in rules.items():
        # If any of the rules match, we block the request
        if pattern.search(request.path) or pattern.search(request.query_string.decode()):
            abort(403, description=f'Request blocked by WAF: Detected {attack_type}')

## Actual website code on flask side
@app.route('/')
def home():
    return 'Welcome to a website protected by a WAF!'

@app.route('/unreachable')
def unreachable():
    return 'This page is unreachable!'


# Start the web application on port 5000
if __name__ == '__main__':
    app.run(port=5000)