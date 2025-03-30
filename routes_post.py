from flask import render_template, request, redirect, url_for, flash, session, flash
from app import app
from models import db, Admin, User, Subject, Chapter, Quiz, Question, Score, Option
from werkzeug.security import generate_password_hash, check_password_hash
from auth import auth_required, admin_required, user_required
from datetime import datetime




"""---------------------- POST ROUTES ----------------------"""

# ---------------------- LOGIN ROUTE ----------------------
@app.route('/login', methods=['POST'])
@app.route('/', methods=['POST'])
def login_post():
    """Handles both user and admin login logic."""
    username = request.form.get('username')
    password = request.form.get('password')

    if not username or not password:
        flash('Please enter both username and password.')
        return redirect(url_for('login'))

    # Check if user exists in User table
    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.password, password):
        session['user_id'] = user.id
        flash('Login successful!')
        return redirect(url_for('user_home'))

    # If not a normal user, check Admin table
    admin = Admin.query.filter_by(username=username).first()
    if admin and check_password_hash(admin.password, password):
        session['admin_id'] = admin.id
        flash('Admin login successful!')
        return redirect(url_for('admin_home'))

    
    flash('Invalid username or password!')
    return redirect(url_for('login'))


# ---------------------- LOGOUT ROUTE ----------------------
@app.route('/logout')
@auth_required
def logout():
    """Logs out user or admin."""
    session.pop('user_id', None)
    session.pop('admin_id', None)
    flash('You have been logged out.')
    return redirect(url_for('login'))

# ---------------------- REGISTER ROUTE ----------------------


@app.route('/register', methods=['POST'])
def register_post():
    """Handles user registration."""
    username = request.form.get('username')
    password = request.form.get('password')
    full_name = request.form.get('full_name')
    dob = request.form.get('dob')
    qualification = request.form.get('qualification')
    confirm_password = request.form.get('confirm_password')

    if not username or not password or not confirm_password:
        flash('All fields are required.')
        return redirect(url_for('register'))

    if password != confirm_password:
        flash('Passwords do not match!')
        return redirect(url_for('register'))

    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        flash('Username already taken.')
        return redirect(url_for('register'))
    
    dob = datetime.strptime(dob, '%Y-%m-%d').date()

    hashed_password = generate_password_hash(password)
    new_user = User(username=username, password=hashed_password, full_name=full_name, dob=dob, qualification=qualification)


    db.session.add(new_user)
    db.session.commit()

    flash('Registration successful! Please log in.')
    return redirect(url_for('login'))


# ---------------------- ADMIN UPDATE PROFILE ----------------------

@app.route('/admin/update_profile', methods=['POST'])
@admin_required
def update_profile_post():
    admin = Admin.query.get(session['admin_id'])
    
    admin.name = request.form.get('name')
    admin.phone = request.form.get('phone')
    password = request.form.get('password')
    
    if password:
        admin.password = generate_password_hash(password)
    
    db.session.commit()
    flash('Profile updated successfully!')
    return redirect(url_for('admin_home'))


# ---------------------- USER DELETE ----------------------

@app.route('/admin/user/delete/<int:user_id>', methods=['POST'])
@admin_required  # Only admin can delete users
def user_delete_post(user_id):
    admin = Admin.query.get(session['admin_id'])  # Get admin details
    user = User.query.get(user_id)  # Get user to be deleted

    db.session.delete(user)
    db.session.commit()
    
    flash("User deleted successfully.")
    return redirect(url_for('admin_nav_users'))

# ---------------------- CREATE NEW SUBJECT ----------------------
@app.route('/admin/create/subject_add', methods=['POST'])
@admin_required
def subject_add_post():
    admin = Admin.query.get(session['admin_id'])  # Get admin details
    
    subject_name = request.form.get('subject_name')
    description = request.form.get('description')

    # Check if the subject already exists
    existing_subject = Subject.query.filter_by(name=subject_name).first()
    if existing_subject:
        flash('Subject already exists!')
        return redirect(url_for('subject_add'))

    # Create new subject
    new_subject = Subject(name=subject_name, description=description)
    db.session.add(new_subject)
    db.session.commit()

    flash('Subject added successfully!')
    return redirect(url_for('admin_nav_subjects'))

# ---------------------- CREATE NEW CHAPTER ----------------------
@app.route('/admin/create/chapter_add', methods=['POST'])
@admin_required
def chapter_add_post():
    admin = Admin.query.get(session['admin_id'])
    
    chapter_name = request.form.get('chapter_name')
    description = request.form.get('description')
    subject_id = request.form.get('subject_id')

    # Check if chapter already exists under the same subject
    existing_chapter = Chapter.query.filter_by(name=chapter_name, subject_id=subject_id).first()
    if existing_chapter:
        flash('Chapter already exists in this subject!')
        return redirect(url_for('chapter_add', subject_id=subject_id))

    # Create new chapter
    new_chapter = Chapter(name=chapter_name, description=description, subject_id=subject_id)
    db.session.add(new_chapter)
    db.session.commit()

    flash('Chapter added successfully!')
    return redirect(url_for('admin_subject', subject_id=subject_id))  # Redirect to the subject page


# ---------------------- CREATE NEW QUIZ ----------------------

@app.route('/admin/create/quiz_add', methods=['POST'])
@admin_required
def quiz_add_post():
    admin = Admin.query.get(session['admin_id'])

    quiz_name = request.form.get('quiz_name')
    description = request.form.get('description')
    chapter_id = request.form.get('chapter_id')
    duration = request.form.get('duration')
    date = request.form.get('date')  # Can be optional

    date = datetime.strptime(date, '%Y-%m-%d').date() if date else None

    # Check if quiz already exists in the same chapter
    existing_quiz = Quiz.query.filter_by(name=quiz_name, chapter_id=chapter_id).first()
    if existing_quiz:
        flash('Quiz already exists in this chapter!')
        return redirect(url_for('quiz_add', chapter_id=chapter_id))

    # Create new quiz
    new_quiz = Quiz(
        name=quiz_name, description=description, 
        chapter_id=chapter_id, duration=duration, date=date if date else None
    )
    db.session.add(new_quiz)
    db.session.commit()

    flash('Quiz created successfully!')
    return redirect(url_for('admin_chapter', chapter_id=chapter_id))  # Redirect to the chapter page



# ---------------------- DELETE SUBJECT ----------------------

@app.route('/subject/delete/<int:subject_id>', methods=['POST'])
def subject_delete_post(subject_id):
    if 'admin_id' not in session:
        flash('Unauthorized access!')
        return redirect(url_for('admin_login'))  # Redirect to login if not authenticated

    subject = Subject.query.get(subject_id)

    # Delete all related chapters (Cascade Delete in DB also works)
    for chapter in subject.chapters:
        db.session.delete(chapter)

    # Delete the subject itself
    db.session.delete(subject)
    db.session.commit()

    flash('Subject deleted successfully!')
    return redirect(url_for('admin_nav_subjects'))  # Redirect to subjects list

# ---------------------- EDIT SUBJECT ----------------------
@app.route('/admin/subject_edit/<int:subject_id>', methods=['POST'])
@admin_required
def subject_edit_post(subject_id):
    """Update subject details."""
    if 'admin_id' not in session:
        flash('Unauthorized access!')
        return redirect(url_for('admin_login'))  # Redirect to login if not authenticated

    admin = Admin.query.get(session['admin_id'])  # Get logged-in admin details
    subject = Subject.query.get(subject_id)

    # Get form data
    subject.name = request.form['name'].strip()
    subject.description = request.form['description'].strip()

    # Save changes
    db.session.commit()

    flash('Subject updated successfully!')
    return redirect(url_for('admin_nav_subjects'))

# ---------------------- DELETE CHAPTER ----------------------
@app.route('/chapter/delete/<int:chapter_id>', methods=['POST'])
@admin_required
def chapter_delete_post(chapter_id):
    admin = Admin.query.get(session['admin_id'])  # Ensure admin is logged in
    chapter = Chapter.query.get(chapter_id)

    # Delete the chapter
    db.session.delete(chapter)
    db.session.commit()

    flash('Chapter deleted successfully!')
    return redirect(url_for('admin_subject', subject_id=chapter.subject_id))  # Redirect to subject page

# ---------------------- EDIT CHAPTER ----------------------

@app.route('/admin/chapter/edit/<int:chapter_id>', methods=['POST'])
@admin_required
def chapter_edit_post(chapter_id):
    admin = Admin.query.get(session['admin_id'])  # Ensure admin is logged in
    chapter = Chapter.query.get(chapter_id)

    # Get updated chapter details from the form
    chapter_name = request.form.get('chapter_name')
    description = request.form.get('description')

    # Check if the chapter name already exists in the subject
    existing_chapter = Chapter.query.filter_by(name=chapter_name, subject_id=chapter.subject_id).first()
    if existing_chapter and existing_chapter.id != chapter.id:
        flash('Chapter with this name already exists under the subject!')
        return redirect(url_for('chapter_edit', chapter_id=chapter.id))

    # Update chapter details
    chapter.name = chapter_name
    chapter.description = description
    db.session.commit()

    flash('Chapter updated successfully!')
    return redirect(url_for('admin_subject', subject_id=chapter.subject_id))


# ---------------------- DELETE QUIZ ----------------------
@app.route('/admin/quiz/delete/<int:quiz_id>', methods=['POST'])
@admin_required  # Ensures that only logged-in admins can access this route
def quiz_delete_post(quiz_id):
    # Ensure the admin session is active
    admin = Admin.query.get(session.get('admin_id'))  # Fetching the logged-in admin by ID from session

    # If no admin is found in session, redirect to login page or handle error
    if not admin:
        flash('You must be logged in to delete a quiz.')
        return redirect(url_for('login'))  # Replace 'login' with your login route

    quiz = Quiz.query.get(quiz_id)

    # Deleting the quiz
    db.session.delete(quiz)
    db.session.commit()

    flash('Quiz deleted successfully!')
    return redirect(url_for('admin_chapter', chapter_id=quiz.chapter_id))

# ---------------------- EDIT QUIZ ----------------------
@app.route('/admin/edit/quiz/<int:quiz_id>', methods=['POST'])
def quiz_edit_post(quiz_id):
    # Check if admin is logged in
    if 'admin_id' not in session:
        flash('Unauthorized access!')
        return redirect(url_for('admin_login'))  # Redirect to login if not authenticated

    # Retrieve the quiz by ID
    quiz = Quiz.query.get_or_404(quiz_id)

    # Get form data
    quiz_name = request.form['quiz_name']
    description = request.form['description']
    duration = request.form['duration']
    date = request.form.get('date')

    # Update the quiz
    quiz.name = quiz_name
    quiz.description = description
    quiz.duration = duration
    quiz.date = datetime.strptime(date, '%Y-%m-%d').date() if date else None

    # Commit changes to the database
    db.session.commit()

    flash('Quiz updated successfully!')
    return redirect(url_for('admin_chapter', chapter_id=quiz.chapter_id))


# ---------------------- ADD QUESTION ----------------------
@app.route('/quiz/<int:quiz_id>/add_question', methods=['POST'])
@admin_required
def question_add_post(quiz_id):
    # Ensure the user is an admin
    if 'admin_id' not in session:
        return redirect(url_for('login'))  # Redirect to login page if no admin session exists
    
    admin = Admin.query.get(session['admin_id'])  # Get the admin from the session
    quiz = Quiz.query.get(quiz_id)  # Get the quiz by its ID

    # Get the form data
    question_text = request.form['question']
    explanation_text = request.form['explanation']
    marks = int(request.form['marks'])

    # Create a new question instance
    new_question = Question(
        quiz_id=quiz.id,
        question=question_text,
        explanation=explanation_text,
        marks=marks
    )

    # Add the new question to the database
    db.session.add(new_question)
    db.session.commit()

    # Redirect to the quiz page or another page as needed
    return redirect(url_for('admin_quiz', quiz_id=quiz.id))

# ---------------------- DELETE QUESTION ----------------------
@app.route('/admin/question/delete/<int:question_id>', methods=['POST'])
@admin_required  # Ensures that only logged-in admins can access this route
def question_delete_post(question_id):
    # Ensure the admin session is active
    admin = Admin.query.get(session.get('admin_id'))  # Fetching the logged-in admin by ID from session

    # If no admin is found in session, redirect to login page or handle error
    if not admin:
        flash('You must be logged in to delete a question.')
        return redirect(url_for('login'))  # Replace 'login' with your login route

    # Fetch the question to be deleted
    question = Question.query.get_or_404(question_id)

    # Get the related quiz to redirect after deletion
    quiz = question.quiz

    # Delete the question from the database
    db.session.delete(question)
    db.session.commit()

    flash('Question deleted successfully!')
    return redirect(url_for('admin_quiz', quiz_id=quiz.id))

# ---------------------- EDIT QUESTION ----------------------

@app.route('/admin/question/edit/<int:question_id>', methods=['POST'])
@admin_required  # Ensure the user is an admin
def question_edit_post(question_id):
    admin = Admin.query.get(session['admin_id'])  # Fetch the logged-in admin by ID from the session

    if not admin:
        flash('You must be logged in to edit a question.')
        return redirect(url_for('login'))  # Redirect to login if not logged in

    question = Question.query.get(question_id)  # Fetch the question by ID
    if question:
        question.question = request.form['question']  # Update the question text
        question.explanation = request.form['explanation']  # Update the explanation
        question.marks = request.form['marks']  # Update the marks

        db.session.commit()  # Commit the changes to the database

        flash('Question updated successfully!')
        return redirect(url_for('admin_quiz', quiz_id=question.quiz.id))  # Redirect back to the quiz page


# ---------------------- ADD OPTION ----------------------

@app.route('/admin/question/<int:question_id>/option/add', methods=['POST'])
@admin_required  # Ensures only logged-in admins can access this route
def option_add_post(question_id):
    # Ensure the admin session is active
    admin = Admin.query.get(session.get('admin_id'))

    # If no admin is found in session, redirect to login page or handle error
    if not admin:
        flash('You must be logged in to add an option.')
        return redirect(url_for('login'))  # Replace 'login' with your login route

    # Fetch the question to which the option will be added
    question = Question.query.get(question_id)
    if not question:
        flash('Question not found.')
        return redirect(url_for('admin_question', question_id=question_id))  # Redirect if question is not found

    # Get the data from the form
    option_text = request.form['option_text']
    is_correct = 'is_correct' in request.form  # Checkbox will be checked if is_correct is present in the form

    # Check if the option already exists
    existing_option = Option.query.filter_by(option_text=option_text, question_id=question.id).first()
    if existing_option:
        flash('This option already exists.')
        return redirect(url_for('admin_question', question_id=question.id))  # Redirect if option already exists

    # Check if any existing options have is_correct set to True
    if is_correct:
        existing_correct_option = Option.query.filter_by(question_id=question.id, is_correct=True).first()
        if existing_correct_option:
            flash('Only one option can be marked as correct.')
            return redirect(url_for('admin_question', question_id=question.id))  # Redirect if there's already a correct option

    # Create a new option
    new_option = Option(option_text=option_text, is_correct=is_correct, question_id=question.id)

    # Add the new option to the database
    db.session.add(new_option)
    db.session.commit()

    flash('Option added successfully!')
    return redirect(url_for('admin_question', question_id=question.id))  # Redirect to the question view page


# ---------------------- DELETE OPTION ----------------------

@app.route('/admin/question/<int:question_id>/option/delete/<int:option_id>', methods=['POST'])
@admin_required  # Ensures only logged-in admins can access this route
def option_delete_post(question_id, option_id):
    # Ensure the admin session is active
    admin = Admin.query.get(session.get('admin_id'))

    # If no admin is found in session, redirect to login page or handle error
    if not admin:
        flash('You must be logged in to delete an option.')
        return redirect(url_for('login'))  # Replace 'login' with your login route

    # Fetch the option to be deleted
    option = Option.query.get(option_id)
    if not option:
        flash('Option not found.')
        return redirect(url_for('admin_question', question_id=question_id))  # Redirect if option is not found

    # Deleting the option
    db.session.delete(option)
    db.session.commit()

    flash('Option deleted successfully!')
    return redirect(url_for('admin_question', question_id=question_id))  # Redirect to the question view page



# ---------------------- EDIT OPTION ----------------------
@app.route('/admin/option/edit/<int:option_id>', methods=['POST'])
@admin_required
def option_edit_post(option_id):
    """Handles POST request to update an option."""
    option = Option.query.get(option_id)
    if not option:
        flash('Option not found!', 'danger')
        return redirect(url_for('admin_home'))

    # Get form data
    option_text = request.form['option_text']
    is_correct = 'is_correct' in request.form  # If checked, 'is_correct' will be in the form data
    question_id = option.question_id

    # Check if the new option text already exists for the same question
    existing_option = Option.query.filter_by(question_id=question_id, option_text=option_text).first()
    if existing_option and existing_option.id != option_id:
        flash('This option text already exists for the question!', 'danger')
        return redirect(url_for('admin_question', question_id=question_id))

    # If 'is_correct' is checked, ensure no other option is already marked as correct for the same question
    if is_correct:
        existing_correct_option = Option.query.filter_by(question_id=question_id, is_correct=True).first()
        if existing_correct_option and existing_correct_option.id != option_id:
            flash('Only one option can be marked as correct. Please uncheck the other option first.', 'danger')
            return redirect(url_for('admin_question', question_id=question_id))

    # Update the option details
    option.option_text = option_text
    option.is_correct = is_correct

    # Commit the changes to the database
    try:
        db.session.commit()
        flash('Option updated successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating option: {e}', 'danger')

    return redirect(url_for('admin_question', question_id=question_id))



#-----------------------UPDATE USER PROFILE ----------------------
@app.route('/user/update_profile', methods=['POST'])
@user_required
def user_update_profile_post():
    """Handles POST request for updating user profile."""
    user = User.query.get(session['user_id'])  # Fetch the logged-in user's details

    # Get form data
    username = request.form['username']
    full_name = request.form['full_name']
    qualification = request.form['qualification']
    dob = request.form['dob']

    # Check if the date of birth is in the correct format (yyyy-mm-dd)
    try:
        dob = datetime.strptime(dob, '%Y-%m-%d').date()
    except ValueError:
        flash('Invalid Date of Birth format. Please use YYYY-MM-DD.', 'danger')
        return redirect(url_for('user_update_profile'))

    # Check if the username is being changed and if the new username already exists
    if username != user.username and User.query.filter_by(username=username).first():
        flash('Username already exists. Please choose a different one.', 'danger')
        return redirect(url_for('user_update_profile'))

    # Update user's profile details
    user.username = username
    user.full_name = full_name
    user.qualification = qualification
    user.dob = dob

    # Commit the changes to the database
    try:
        db.session.commit()
        flash('Profile updated successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating profile: {e}', 'danger')
        return redirect(url_for('user_update_profile'))

    return redirect(url_for('user_profile'))  # Redirect to profile page after updating


# ---------------------- TAKE QUIZ ----------------------
@app.route('/user/quiz/take/<int:quiz_id>', methods=['GET', 'POST'])
@user_required
def take_quiz(quiz_id):
    user = User.query.get(session['user_id'])
    quiz = Quiz.query.get(quiz_id)

    # Get all questions for the quiz
    questions = Question.query.filter_by(quiz_id=quiz.id).all()

    if request.method == 'POST':
        # Collect answers from form
        answers = request.form.getlist('answer')  # Get all answers (one for each question)

        # Initialize variable for scoring
        score = 0

        for i, question in enumerate(questions):
            # Check if there is an answer for this question
            if i < len(answers) and answers[i]:  # Only process if the answer exists
                option = Option.query.get(answers[i])
                if option and option.is_correct:
                    score += 1  # Increment score for correct answer

        # Create a Score entry and save to the database
        score_entry = Score(
            quiz_id=quiz.id,
            user_id=user.id,
            score=score
        )
        db.session.add(score_entry)
        db.session.commit()

        # Redirect to the results page
        return redirect(url_for('quiz_result', score_id=score_entry.id))

    return render_template('user_pages/take_quiz.html', quiz=quiz, questions=questions)







