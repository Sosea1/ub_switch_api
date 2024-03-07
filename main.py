#!/bin/python3
from flask import Flask


app = Flask(__name__)

@app.route("/")
def hello_world():
    return "<p>Hello, World!</p>"


@app.route("/tests")
def route_tests():
    import Tests.utils
    return Tests.utils.makeRequest('tcp:127.0.0.1:6640', 'get_schema', ['Open_vSwitch']).result


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8080)