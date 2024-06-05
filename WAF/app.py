from flask import Flask, request, jsonify
import waf_rules
import logging

logging.basicConfig(filename='waf.log', level=logging.INFO, format='%(asctime)s %(message)s')

def log_request(request, blocked):
    status = "Blocked" if blocked else "Allowed"
    logging.info(f"{status} request: {request.remote_addr} {request.method} {request.url} {request.data}")

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    blocked = waf_rules.is_request_blocked(request)
    log_request(request, blocked)
    if blocked:
        return jsonify({"message": "Request blocked by WAF"}), 403
    return jsonify({"message": "Request allowed"}), 200

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)