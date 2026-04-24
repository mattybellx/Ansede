from flask import Blueprint, request

bp = Blueprint('auth', __name__, url_prefix='/auth')

@bp.route('/register', methods=('GET', 'POST'))
def register():
    username = request.form['username']
    password = request.form['password']
    
    query = "INSERT INTO " + username
    db.execute(query)
    
    return "done"
