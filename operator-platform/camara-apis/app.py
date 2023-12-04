import os
from flask import Flask, jsonify
from gevent.pywsgi import WSGIServer

app = Flask(__name__)
port = int(os.environ.get('PORT', 5000))

#
# Simulate an exposed CAMARA API (Device Location)
# with a hardcoded response.
#
@app.route('/device-location-verification/v1/verify', methods=['POST'])
def device_location():
    dummmy_response_data = {
        "verification_result": "match"
    }
    return jsonify(dummmy_response_data)

@app.route('/number-verification-rc/v1/verify-hashed', methods=['POST'])
def number_verification():
    dummmy_response_data = {
        "device_phone_number_verified": "match"
    }
    return jsonify(dummmy_response_data)

@app.route('/healthz')
def healthz():
    return 'OK'


if __name__ == '__main__':
    http_server = WSGIServer(('0.0.0.0', port), app)
    http_server.serve_forever()
