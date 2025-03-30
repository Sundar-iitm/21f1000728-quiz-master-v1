from functools import wraps
from flask import session, redirect, url_for, flash
from models import Admin, User  # Importing models

def auth_required(func):
    """Allows access to any logged-in user (Admin or User)."""
    @wraps(func)
    def inner(*args, **kwargs):
        if 'user_id' in session or 'admin_id' in session:
            return func(*args, **kwargs)
        else:
            flash('You need to login first!', 'danger')
            return redirect(url_for('login'))
    return inner

def admin_required(func):
    """Restricts access to Admins only."""
    @wraps(func)
    def inner(*args, **kwargs):
        if 'admin_id' not in session:  # Only check admin session
            flash('You need to be an admin to access this page!', 'danger')
            return redirect(url_for('login'))
        return func(*args, **kwargs)
    return inner

def user_required(func):
    """Restricts access to regular Users only."""
    @wraps(func)
    def inner(*args, **kwargs):
        if 'user_id' not in session:  # Only check user session
            flash('You need to be logged in as a user!', 'danger')
            return redirect(url_for('login'))
        return func(*args, **kwargs)
    return inner
