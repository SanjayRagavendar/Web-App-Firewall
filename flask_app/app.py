from flask import Flask, render_template, request, redirect, url_for, flash

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this to a random secret key

# Mock user data (replace this with a proper authentication system)
users = {'aaron': 'test', 'sanjay': 'test'}

@app.route('/')
def home():
    return 'Welcome to the Flask Login Example!'

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username in users and users[username] == password:
            flash('Login successful!', 'success')
            return render_template('successful_login.html')
        else:
            flash('Invalid username or password. Please try again.', 'error')

    return render_template('login.html')


if __name__ == '__main__':
    app.run(debug=True)
