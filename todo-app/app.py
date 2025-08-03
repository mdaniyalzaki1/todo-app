from flask import Flask, redirect, render_template, request, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'a-fallback-secret-key-for-development')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todos.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# ===========================
# Models
# ===========================

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    todos = db.relationship('Todo', backref='user', lazy=True)

    def hash_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)


class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    todo = db.Column(db.String(150), nullable=False)
    done = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"<Todo {self.id}>"

# ===========================
# Routes
# ===========================

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        existing_user = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()

        if existing_user:
            flash('Username or email already exists.')
            return redirect(url_for('signup'))

        new_user = User(username=username, email=email)
        new_user.hash_password(password)
        db.session.add(new_user)
        db.session.commit()

        flash('Signup successful! You can log in now.')
        return redirect(url_for('login'))

    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        identifier = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter(
            (User.username == identifier) | (User.email == identifier)
        ).first()

        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Login successful!')
            return redirect(url_for('index'))

        flash('Invalid username/email or password.')
        return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.')
    return redirect(url_for('login'))


@app.route('/')
def index():
    if 'user_id' not in session:
        flash('Please login first.')
        return redirect(url_for('signup'))

    user_id = session['user_id']
    todos = Todo.query.filter_by(user_id=user_id).all()
    return render_template('index.html', todos=todos)


@app.route('/add', methods=['POST'])
def add_todo():
    if 'user_id' not in session:
        flash('You need to log in to add todos.')
        return redirect(url_for('login'))

    todo_text = request.form.get('todo')
    if todo_text:
        new_todo = Todo(todo=todo_text, user_id=session['user_id'])
        db.session.add(new_todo)
        db.session.commit()
        flash('Todo added.')

    return redirect(url_for('index'))


@app.route('/done/<int:todo_id>')
def mark_done(todo_id):
    if 'user_id' not in session:
        flash('Login required.')
        return redirect(url_for('login'))

    todo = Todo.query.get_or_404(todo_id)
    if todo.user_id != session['user_id']:
        flash('Not allowed.')
        return redirect(url_for('index'))

    todo.done = True
    db.session.commit()
    flash('Marked as done!')
    return redirect(url_for('index'))


@app.route('/delete/<int:todo_id>')
def delete_todo(todo_id):
    if 'user_id' not in session:
        flash('Login required.')
        return redirect(url_for('login'))

    todo = Todo.query.get_or_404(todo_id)
    if todo.user_id != session['user_id']:
        flash('Not allowed.')
        return redirect(url_for('index'))

    db.session.delete(todo)
    db.session.commit()
    flash('Todo deleted.')
    return redirect(url_for('index'))

# ===========================
# Initialize DB Tables
# ===========================

with app.app_context():
    db.create_all()

# ===========================
# Run App
# ===========================

if __name__ == '__main__':
    app.run(debug=True)
