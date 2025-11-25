from flask import Flask, abort

app = Flask(__name__)


# Route for root URL
@app.route('/')
def root():
    return 'root page'

# Route for home URL
@app.route('/home')
def home():
    return 'Home page'

# Route for about URL
@app.route('/about')
def about():
    return 'About page'

# Route for Results URL
@app.route('/results')
def results():
    return 'Results page'

# Route for login URL
@app.route('/login')
def login():
    return 'Login page'

# Route for signup URL
@app.route('/signup')
def signup():
    return 'Signup page'

# Route for dashboard URL
@app.route('/dashboard')
def dashboard():
    return 'Dashboard page'

# Route for profile URL
@app.route('/profile')
def profile():
    return 'Profile page'





if __name__ == '__main__':
    app.run(debug=True, port=8888, host='127.0.0.1')
