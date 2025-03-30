from flask import render_template, request, redirect, url_for, flash, session
from app import app
from models import db, Admin, User, Subject, Chapter, Quiz, Question, Score, Option
from werkzeug.security import generate_password_hash, check_password_hash
from auth import auth_required, admin_required, user_required
from datetime import datetime

"""---------------------- GET ROUTES ----------------------"""

# -------------------- Other Pages --------------------
@app.route('/login')
@app.route('/')
def login():
    return render_template('other_pages/login.html')

@app.route('/register')
def register():
    return render_template('other_pages/register.html')

# -------------------- Admin Pages --------------------

@app.route('/chapter/view/<int:chapter_id>', methods=['GET'])
@admin_required
def admin_chapter(chapter_id):
    admin = Admin.query.get(session['admin_id'])
    chapter = Chapter.query.get(chapter_id)
    return render_template('admin_pages/chapter.html', admin=admin, chapter=chapter)


@app.route('/admin/create')
@admin_required
def admin_create():
    admin = Admin.query.get(session['admin_id'])
    return render_template('admin_pages/create.html', admin=admin)

@app.route('/admin/home')
@admin_required
def admin_home():
    admin = Admin.query.get(session['admin_id'])
    return render_template('admin_pages/home.html', admin=admin)


@app.route('/admin/admin_nav_subjects')
@admin_required
def admin_nav_subjects():
    admin = Admin.query.get(session['admin_id'])
    subjects = Subject.query.all()  # Fetch all subjects
    return render_template('admin_pages/nav_subjects.html', admin=admin, subjects=subjects)



@app.route('/admin/nav_users')
@admin_required
def admin_nav_users():
    users = User.query.all()  # Fetch all users from the database
    admin = Admin.query.get(session['admin_id'])
    return render_template('admin_pages/nav_users.html', admin=admin, users=users)


@app.route('/admin/question/view/<int:question_id>', methods=['GET'])
@admin_required  # Ensures that only logged-in admins can access this route
def admin_question(question_id):
    # Ensure the admin session is active
    admin = Admin.query.get(session.get('admin_id'))  # Fetching the logged-in admin by ID from session

    # If no admin is found in session, redirect to login page or handle error
    if not admin:
        flash('You must be logged in to view the question details.')
        return redirect(url_for('login'))  # Replace 'login' with your login route

    question = Question.query.get(question_id)

    # Render the page that will display the question and its options
    return render_template('admin_pages/question.html', question=question)



@app.route('/admin/quiz/<int:quiz_id>', methods=['GET'])
def admin_quiz(quiz_id):
    # Check if admin is logged in
    if 'admin_id' not in session:
        flash('Unauthorized access!')
        return redirect(url_for('login'))  # Redirect to admin login page if not authenticated
    
    quiz = Quiz.query.get(quiz_id)

    # Render quiz details page
    return render_template('admin_pages/quiz.html', quiz=quiz)


@app.route('/admin/search', methods=['GET'])
@admin_required  # Ensure only admin can access this route
def admin_search():
    query = request.args.get('query', '')
    search_type = request.args.get('search_type', 'users')

    # Initialize the result dictionary
    results = {
        'users': [],
        'subjects': [],
        'chapters': [],
        'quizzes': []
    }

    # Handle the search based on search_type
    if search_type == 'users':
        results['users'] = User.query.filter(
            (User.username.ilike(f'%{query}%')) | (User.id.ilike(f'%{query}%'))
        ).all()
    elif search_type == 'subjects':
        results['subjects'] = Subject.query.filter(
            (Subject.name.ilike(f'%{query}%')) | (Subject.id.ilike(f'%{query}%'))
        ).all()
    elif search_type == 'chapters':  
        results['chapters'] = Chapter.query.filter(
            (Chapter.name.ilike(f'%{query}%')) | (Chapter.id.ilike(f'%{query}%'))
        ).all()
    elif search_type == 'quizzes':
        results['quizzes'] = Quiz.query.filter(
            (Quiz.name.ilike(f'%{query}%')) | (Quiz.id.ilike(f'%{query}%'))
        ).all()

    return render_template('admin_pages/search.html', results=results)






@app.route('/subject/view/<int:subject_id>', methods=['GET'])
@admin_required
def admin_subject(subject_id):
    admin = Admin.query.get(session['admin_id'])  # Ensure admin is logged in
    subject = Subject.query.get(subject_id)
    return render_template('admin_pages/subject.html', admin=admin, subject=subject)


@app.route('/admin/summary')
@admin_required
def admin_summary():
    # Fetch the total number of users
    total_users = User.query.count()

    # Fetch the total number of quizzes
    total_quizzes = Quiz.query.count()

    # Fetch the total number of subjects
    total_subjects = Subject.query.count()

    # Fetch the total number of chapters
    total_chapters = Chapter.query.count()

    # Fetch the average score for all users
    all_scores = Score.query.all()
    total_scores = sum([score.score for score in all_scores])
    total_score_count = len(all_scores)
    average_score = total_scores / total_score_count if total_score_count else 0

    return render_template('admin_pages/summary.html', total_users=total_users, total_quizzes=total_quizzes,total_subjects=total_subjects, total_chapters=total_chapters,average_score=average_score)



@app.route('/admin/update_profile')
@admin_required
def admin_update_profile():
    admin = Admin.query.get(session['admin_id'])
    return render_template('admin_pages/update_profile.html', admin=admin)


@app.route('/admin/user/<int:user_id>')
@admin_required  # Only admin can access this page
def admin_user(user_id):
    admin = Admin.query.get(session['admin_id'])  # Get admin details
    user = User.query.get(user_id)  # Fetch user details
    return render_template('admin_pages/user.html', admin=admin, user=user)


# -------------------- CRUD Pages --------------------

#-------------------- Chapter Pages --------------------

@app.route('/admin/create/chapter_add')
@admin_required
def chapter_add():
    admin = Admin.query.get(session['admin_id'])
    subjects = Subject.query.all()  # Get all subjects for selection
    return render_template('CRUD/chapter_add.html', admin=admin, subjects=subjects)





@app.route('/chapter/delete/<int:chapter_id>', methods=['GET'])
@admin_required
def chapter_delete(chapter_id):
    admin = Admin.query.get(session['admin_id'])  # Ensure admin is logged in
    chapter = Chapter.query.get(chapter_id)
    
    return render_template('CRUD/chapter_delete.html', admin=admin, chapter=chapter)


@app.route('/admin/chapter/edit/<int:chapter_id>', methods=['GET'])
@admin_required
def chapter_edit(chapter_id):
    admin = Admin.query.get(session['admin_id'])  # Ensure admin is logged in
    chapter = Chapter.query.get(chapter_id)
    return render_template('CRUD/chapter_edit.html', admin=admin, chapter=chapter)

#-------------------- question Pages --------------------


@app.route('/quiz/<int:quiz_id>/add_question', methods=['GET'])
@admin_required
def question_add(quiz_id):
    admin = Admin.query.get(session['admin_id'])  # Get admin details from the session
    quiz = Quiz.query.get(quiz_id)  # Get the quiz by its ID
    return render_template('CRUD/question_add.html', admin=admin, quiz=quiz)




@app.route('/admin/question/delete/<int:question_id>', methods=['GET'])
@admin_required  # Ensures that only logged-in admins can access this route
def question_delete(question_id):
    # Ensure the admin session is active
    admin = Admin.query.get(session.get('admin_id'))  # Fetching the logged-in admin by ID from session

    # If no admin is found in session, redirect to login page or handle error
    if not admin:
        flash('You must be logged in to delete a question.')
        return redirect(url_for('login'))  # Replace 'login' with your login route

    # Fetch the question to be deleted
    question = Question.query.get(question_id)
    
    # Render the delete confirmation page with the question details
    return render_template('CRUD/question_delete.html', question=question)


@app.route('/admin/question/edit/<int:question_id>', methods=['GET'])
@admin_required  # Ensure the user is an admin
def question_edit(question_id):
    admin = Admin.query.get(session['admin_id'])  # Fetch the logged-in admin by ID from the session

    if not admin:
        flash('You must be logged in to edit a question.')
        return redirect(url_for('login'))  # Redirect to login if not logged in

    question = Question.query.get(question_id)  # Fetch the question by ID
    return render_template('CRUD/question_edit.html', question=question)


# -------------------- Quiz Pages --------------------


@app.route('/admin/create/quiz_add')
@admin_required
def quiz_add():
    admin = Admin.query.get(session['admin_id'])
    chapters = Chapter.query.all()  # Get all chapters for selection
    return render_template('CRUD/quiz_add.html', admin=admin, chapters=chapters)




@app.route('/admin/quiz/delete/<int:quiz_id>', methods=['GET'])
@admin_required  # Ensures that only logged-in admins can access this route
def quiz_delete(quiz_id):
    # Ensure the admin session is active
    admin = Admin.query.get(session.get('admin_id'))  # Fetching the logged-in admin by ID from session

    # If no admin is found in session, redirect to login page or handle error
    if not admin:
        flash('You must be logged in to delete a quiz.')
        return redirect(url_for('login'))  # Replace 'login' with your login route

    quiz = Quiz.query.get(quiz_id)
    return render_template('CRUD/quiz_delete.html', quiz=quiz)




@app.route('/admin/edit/quiz/<int:quiz_id>', methods=['GET'])
def quiz_edit(quiz_id):
    # Check if admin is logged in
    if 'admin_id' not in session:
        flash('Unauthorized access!')
        return redirect(url_for('login'))  # Redirect to login if not authenticated

    # Retrieve the quiz by ID
    quiz = Quiz.query.get(quiz_id)
    
    return render_template('CRUD/quiz_edit.html', quiz=quiz)



# -------------------- Subject Pages --------------------
@app.route('/admin/create/subject_add', methods=['GET'])
@admin_required
def subject_add():
    admin = Admin.query.get(session['admin_id'])
    return render_template('CRUD/subject_add.html', admin=admin)



@app.route('/admin/subject_delete/<int:subject_id>', methods=['GET'])
@admin_required
def subject_delete(subject_id):
    admin = Admin.query.get(session['admin_id'])  # Ensure admin is logged in
    subject = Subject.query.get(subject_id)
    return render_template('CRUD/subject_delete.html', admin=admin, subject=subject)



@app.route('/admin/subject_edit/<int:subject_id>', methods=['GET'])
@admin_required
def subject_edit(subject_id):
    """Display subject edit form."""
    if 'admin_id' not in session:
        flash('Unauthorized access!')
        return redirect(url_for('admin_login'))  # Redirect to login if not authenticated

    admin = Admin.query.get(session['admin_id'])  # Get logged-in admin details
    subject = Subject.query.get_or_404(subject_id)
    
    return render_template('CRUD/subject_edit.html', admin=admin, subject=subject)

# -------------------- User Pages --------------------
@app.route('/admin/user_delete/<int:user_id>')
@admin_required  # Only admins can delete users
def user_delete(user_id):
    admin = Admin.query.get(session['admin_id'])  # Get admin details
    user = User.query.get(user_id)  # Fetch user from the database
    return render_template('CRUD/user_delete.html', admin=admin, user=user)


#-------------------- Option Pages --------------------
@app.route('/admin/question/<int:question_id>/option/add', methods=['GET'])
@admin_required  # Ensures only logged-in admins can access this route
def option_add(question_id):
    # Ensure the admin session is active
    admin = Admin.query.get(session.get('admin_id'))

    # If no admin is found in session, redirect to login page or handle error
    if not admin:
        flash('You must be logged in to add an option.')
        return redirect(url_for('login'))  # Replace 'login' with your login route

    # Render the option add form
    return render_template('CRUD/option_add.html', question_id=question_id)


@app.route('/admin/question/<int:question_id>/option/delete/<int:option_id>', methods=['GET'])
@admin_required  # Ensures only logged-in admins can access this route
def option_delete(question_id, option_id):
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

    # Fetch the question for the option
    question = Question.query.get(question_id)
    if not question:
        flash('Question not found.')
        return redirect(url_for('admin_question', question_id=question_id))  # Redirect if question is not found

    return render_template('CRUD/option_delete.html', option=option, question=question)


@app.route('/admin/option/edit/<int:option_id>', methods=['GET'])
@admin_required
def option_edit(option_id):
    """Handles GET request to edit an option."""
    option = Option.query.get(option_id)
    if not option:
        flash('Option not found!')
        return redirect(url_for('admin_home'))

    return render_template('CRUD/option_edit.html', option=option)


#----------------------------------------------------


#-------------------- User Pages --------------------

@app.route('/user/subject/chapter/view/<int:chapter_id>', methods=['GET'])
@user_required  # Ensure the user is logged in
def user_chapter(chapter_id):
    user = User.query.get(session['user_id'])  # Ensure the user is logged in
    chapter = Chapter.query.get(chapter_id)
    return render_template('user_pages/chapter.html', user=user, chapter=chapter)



@app.route('/user/home')
@user_required
def user_home():
    # Get today's date
    today = datetime.today().date()

    # Fetch user ID from session
    user_id = session.get('user_id')

    if not user_id:
        # Handle the case where user_id is not found in the session (optional)
        return redirect(url_for('login'))

    # Fetch all quizzes
    quizzes = Quiz.query.filter((Quiz.date == None) | (Quiz.date == today)).all()

    # Fetch scores related to the current user
    user_scores = Score.query.filter_by(user_id=user_id).all()

    return render_template('user_pages/home.html', quizzes=quizzes, user_scores=user_scores)



@app.route('/user/nav_subjects')
@user_required
def user_nav_subjects():
    # Get user_id from session
    user_id = session.get('user_id')

    if not user_id:
        flash('You must be logged in to view this page.', 'danger')
        return redirect(url_for('login'))  # Redirect to login page if user is not logged in

    # Fetch all subjects from the database
    subjects = Subject.query.all()

    # Fetch user data
    user = User.query.get(user_id)

    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('login'))

    # Render the nav_subjects page with subjects and user data
    return render_template('user_pages/nav_subjects.html', user=user, subjects=subjects)


@app.route('/user/profile')
@user_required
def user_profile():
    user = User.query.get(session['user_id'])
    return render_template('user_pages/profile.html', user=user)


@app.route('/user/quiz/view/<int:quiz_id>', methods=['GET'])
@user_required  # Ensure the user is logged in
def user_quiz(quiz_id):
    user = User.query.get(session['user_id'])  # Ensure the user is logged in
    quiz = Quiz.query.get(quiz_id)
    return render_template('user_pages/quiz.html', user=user, quiz=quiz)


@app.route('/user/update_profile')
@user_required
def user_update_profile():
    user = User.query.get(session['user_id'])
    return render_template('user_pages/update_profile.html', user=user)



@app.route('/user/subject/view/<int:subject_id>', methods=['GET'])
@user_required  
def user_subject(subject_id):
    user = User.query.get(session['user_id'])  # Ensure the user is logged in
    subject = Subject.query.get(subject_id)
    return render_template('user_pages/subject.html', user=user, subject=subject)



@app.route('/user/quiz/take/result/<int:score_id>', methods=['GET'])
@user_required
def quiz_result(score_id):
    score = Score.query.get_or_404(score_id)
    quiz = Quiz.query.get(score.quiz_id)  # Get the quiz associated with this score
    return render_template('user_pages/quiz_result.html', score=score, quiz=quiz)


from flask import render_template, session
from datetime import datetime

@app.route('/user/summary')
@user_required
def user_summary():
    # Fetch user ID from session (assuming it's stored in session)
    user_id = session.get('user_id')
    
    if not user_id:
        return redirect(url_for('login'))

    # Fetch user scores (assuming you have a Score model with user_id, score, and quiz date)
    user_scores = Score.query.filter_by(user_id=user_id).all()

    # Extract quiz dates and scores
    quiz_dates = [score.quiz.date for score in user_scores if score.quiz.date]
    scores = [score.score for score in user_scores]

    # Calculate the number of quizzes completed by date
    date_counts = {date: quiz_dates.count(date) for date in set(quiz_dates)}

    # Calculate score statistics
    total_scores = len(scores)
    average_score = sum(scores) / total_scores if total_scores else 0
    max_score = max(scores) if scores else 0
    min_score = min(scores) if scores else 0

    return render_template('user_pages/summary.html', date_counts=date_counts,total_scores=total_scores, average_score=average_score,max_score=max_score, min_score=min_score)


