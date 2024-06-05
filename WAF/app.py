from flask import Flask, request, jsonify
import waf_rules

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    if waf_rules.is_request_blocked(request):
        return jsonify({"message": "Request blocked by WAF"}), 403
    return jsonify({"message": "Request allowed"}), 200

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)