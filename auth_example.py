from functools import wraps
from werkzeug.security import check_password_hash, generate_password_hash

from flask import abort, Flask, jsonify, redirect, request, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import current_user, login_user, login_required, logout_user, LoginManager, UserMixin
from flask_migrate import Migrate


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///habits.db'

# stores data in the session, without it flask_login does not work
app.secret_key = "secret"

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# ---- simple User ----
class BaseUser(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    role = db.Column(db.String, nullable=False)
    password_hash = db.Column(db.String, nullable=False, default="000")

    def has_permission(self, perm):
        role_perms = {
            "admin": ["view", "edit", "delete"],
            "editor": ["view", "edit"],
            "user": ["view"]
        }
        return perm in role_perms.get(self.role, [])

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class DBAdapter:
    @staticmethod
    def create_user(name, role, password):
        user = BaseUser(name=name, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        return user

    @staticmethod
    def list_users():
        return BaseUser.query.all()

    @staticmethod
    def get_user_by_name(username):
        return BaseUser.query.filter_by(name=username).first_or_404()

    @staticmethod
    def get_user_by_id(user_id):
        return BaseUser.query.get(user_id)


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


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        role = request.form["role"]
        user = DBAdapter.create_user(name=username, role=role, password=password)

        if user:
            login_user(user)
            return redirect(url_for("protected"))

    if request.method == "GET":
        return '''
            <form method="post" style="text-align:center; margin-top:50px;">
                <h2>Registration page</h2>
                <input type="text" name="username" placeholder="Username">
                
                <input type="password" name="password" placeholder="Password">
                
                <label for="role">Role:</label>
                <select name="role" id="role">
                    <option value="admin">admin</option>
                    <option value="editor">editor</option>
                    <option value="user" selected>user</option>
                </select><br><br>
                
                <input type="submit" value="Sign Up">
            </form>
        '''


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        user = DBAdapter.get_user_by_name(username)

        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for("protected"))

    if request.method == "GET":
        return '''
            <form method="post" style="text-align:center; margin-top:50px;">
                <h2>Login page</h2>
                <input type="text" name="username" placeholder="Username">
                <input type="password" name="password" placeholder="Password">
                <input type="submit" value="Login">
            </form>
        '''


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return {"msg": "Logged out!"}


@app.route("/protected")
@login_required
def protected():
    return jsonify({"msg": f"greetings, {current_user.name}. your role is {current_user.role}."})


@app.route("/users", methods=['GET'])
def list_create_api_view():
    return jsonify([
        {"id": user.id, "name": user.name, "role": user.role}
        for user in DBAdapter.list_users()
    ])


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
