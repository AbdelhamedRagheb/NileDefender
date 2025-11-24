from flask import Flask, abort

app = Flask(__name__)


# Route for root URL
@app.route('/')
def home():
    return 'Hello World'


if __name__ == '__main__':
    app.run(debug=True, port=8888, host='127.0.0.1')
