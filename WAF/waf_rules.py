from flask import request

# Simple blacklist of disallowed patterns
disallowed_patterns = [
    '<script>',   # Basic XSS
    'SELECT',     # Basic SQL Injection
    'DROP',       # Basic SQL Injection
    'UNION',      # Basic SQL Injection
    '--',         # SQL Comment
]

def is_request_blocked(request):
    # Check headers, URL, and form data for disallowed patterns
    for pattern in disallowed_patterns:
        if pattern.lower() in request.url.lower():
            return True
        for key, value in request.headers.items():
            if pattern.lower() in key.lower() or pattern.lower() in value.lower():
                return True
        for key, value in request.form.items():
            if pattern.lower() in key.lower() or pattern.lower() in value.lower():
                return True
    return False
