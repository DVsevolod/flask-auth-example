from flask import Flask, render_template, redirect, url_for, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

from functools import wraps
from flask import abort


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///habits.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# хранит данные в сессии, без него flask_login не работает
app.secret_key = "secret"

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

db = SQLAlchemy(app)

# ---- simple User ----
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    role = db.Column(db.String, nullable=False)

    def has_permission(self, perm):
        role_perms = {
            "admin": ["view", "edit", "delete"],
            "editor": ["view", "edit"],
            "user": ["view"]
        }
        return perm in role_perms.get(self.role, [])


class DBAdapter:
    @staticmethod
    def create_user(name, role):
        user = User(name=name, role=role)
        db.session.add(user)
        db.session.commit()
        return user

    @staticmethod
    def list_users():
        return User.query.all()

    @staticmethod
    def get_user_by_name(username):
        return User.query.filter_by(name=username).first_or_404()

    @staticmethod
    def get_user_by_id(user_id):
        return User.query.get(user_id)


# decorator to check permission
def role_required(role):
    def wrapper(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role != role:
                abort(403)
            return f(*args, **kwargs)
        return decorated
    return wrapper


@login_manager.user_loader
def load_user(user_id):
    return DBAdapter.get_user_by_id(user_id)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        user = DBAdapter.get_user_by_name(username)
        if user:
            login_user(user)
            return redirect(url_for("protected"))

    if request.method == "GET":
        return '''
            <form method="post">
                <input type="text" name="username">
                <input type="submit" value="Login">
            </form>
        '''


@app.route("/protected")
@login_required
def protected():
    return jsonify({"msg": f"greetings, {current_user.name}. your role is {current_user.role}."})


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return {"msg": "Logged out!"}


@app.route("/users", methods=['GET', 'POST'])
def list_create_api_view():
    if request.method == 'GET':
        return jsonify([
            {"id": user.id, "name": user.name, "role": user.role}
            for user in DBAdapter.list_users()
        ])

    elif request.method == 'POST':
        data = request.get_json()
        name = data.get('name')
        role = data.get('role')

        if None in [name, role]:
            return jsonify({"status": "error", "msg": f"wrong data, name={name}, role={role}"})

        user = DBAdapter.create_user(name, role)
        if not user:
            return jsonify({"status": "error", "msg": "error while creating user"})

        return jsonify({"status": "success", "user_id": user.id, "user_name": user.name, "user_role": user.role})


@app.route("/admin")
@role_required("admin")
def admin_only():
    return jsonify({"status": "success", "msg": "admin page"})


@app.route("/edit")
@login_required
def edit():
    if not current_user.has_permission("edit"):
        abort(403)
    return jsonify({"status": "success", "msg": "edit page"})


# ---------- init database ---------- #
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
