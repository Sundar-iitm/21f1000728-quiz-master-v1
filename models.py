from flask_sqlalchemy import SQLAlchemy
from app import app
from datetime import datetime
from werkzeug.security import generate_password_hash

db = SQLAlchemy(app)


# Admin Model (Stores Admin login credentials)
class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)


# User Model (Stores registered users' information)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    full_name = db.Column(db.String(200), nullable=False)
    qualification = db.Column(db.String(200), nullable=False)
    dob = db.Column(db.Date, nullable=False)

    # One-to-Many: A User can have multiple scores
    scores = db.relationship('Score', backref='user', cascade="all, delete")


# Subject Model (Stores subjects like Math, Science, etc.)
class Subject(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=False)

    # One-to-Many: A Subject can have multiple Chapters
    chapters = db.relationship('Chapter', backref='subject', cascade="all, delete")


# Chapter Model (Stores chapters related to a subject)
class Chapter(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    subject_id = db.Column(db.Integer, db.ForeignKey('subject.id'), nullable=False)

    # One-to-Many: A Chapter can have multiple Quizzes
    quizzes = db.relationship('Quiz', backref='chapter', cascade="all, delete")


# Quiz Model (Stores quizzes under a chapter)
class Quiz(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    chapter_id = db.Column(db.Integer, db.ForeignKey('chapter.id'), nullable=False)
    duration = db.Column(db.Integer, nullable=False)  # Duration in minutes
    date = db.Column(db.Date, nullable=True)  # Null means quiz can be attempted anytime

    # One-to-Many: A Quiz can have multiple Questions & Scores
    questions = db.relationship('Question', backref='quiz', cascade="all, delete")
    scores = db.relationship('Score', backref='quiz', cascade="all, delete")


# Question Model (Stores MCQ questions for quizzes)
class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable=False)
    question = db.Column(db.Text, nullable=False)
    explanation = db.Column(db.Text, nullable=False)
    marks = db.Column(db.Integer, nullable=False)

    # One-to-Many: A Question can have multiple Options
    options = db.relationship('Option', backref='question', cascade="all, delete")


# Option Model (Stores answer choices for each question)
class Option(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'), nullable=False)
    option_text = db.Column(db.Text, nullable=False)
    is_correct = db.Column(db.Boolean, nullable=False)  # True if this is the correct option


# Score Model (Stores users' quiz attempts and results)
class Score(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now, nullable=False)
    score = db.Column(db.Integer, nullable=False)


# Create tables in the database
with app.app_context():
    db.create_all()

    # Ensure an Admin account exists
    admin = Admin.query.first()

    if not admin:
        password_hash = generate_password_hash('admin123')
        admin = Admin(username='Admin', password=password_hash)
        db.session.add(admin)
        db.session.commit()
