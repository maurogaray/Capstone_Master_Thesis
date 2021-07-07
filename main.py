from flask import Flask, render_template, redirect, request, session
from flask.helpers import send_from_directory, url_for
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from flask_sqlalchemy import SQLAlchemy 
from flask_migrate import Migrate, upgrade
from flask_login import LoginManager, login_user, logout_user
from flask_login.mixins import UserMixin
from flask_login import login_required

from wtforms import StringField, PasswordField
from wtforms.validators import InputRequired, length, Email

from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config["SECRET_KEY"] = "THIS IS A SECRET"
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+pymysql://root:mcsbt@35.242.212.142/mcsbtcap"

Bootstrap(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login = LoginManager()
login.init_app(app)

@login.user_loader
def user_loader(user_id):
    return User.query.filter_by(id=user_id).first()


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String(128), nullable=False)
    lastname = db.Column(db.String(128), nullable=False)
    childname = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(128), nullable=False)
    password = db.Column(db.String(128), nullable=False)


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[Email()])
    password = PasswordField("Password", validators=[length(min=5)])

class RegisterForm(FlaskForm):
    firstname = StringField("First Name", validators=[InputRequired()])
    lastname = StringField("Last Name", validators=[InputRequired()])
    childname = StringField("Child Name", validators=[InputRequired()])
    email = StringField("Email", validators=[Email()])
    password = PasswordField("Password", validators=[length(min=5)])
    repeat_password = PasswordField("Repeat password", validators=[length(min=5)])



@app.route("/")
def index():
    return render_template("index.html")

@app.route("/lp")
@login_required
def lp():
    return render_template("indexLP.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        if check_password_hash(user.password, form.password.data):
            login_user(user)

            if request.form.get('login') == 'parent':
                return redirect(url_for("dashbaord"))
            if request.form.get('login') == 'student':
                return redirect(url_for("lp"))

    return render_template("login.html", form=form)

@app.route("/loginchild", methods=["GET", "POST"])
def loginchild():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        if check_password_hash(user.password, form.password.data):
            login_user(user)

            return redirect(url_for("indexLP"))

@app.route("/loginparent", methods=["GET", "POST"])
def loginparent():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        if check_password_hash(user.password, form.password.data):
            login_user(user)

            return redirect(url_for("dashboard"))

    return render_template("login.html", form=form)


@app.route("/register", methods = ["GET", "POST"])
def register():
    form = RegisterForm()

    if form.validate_on_submit() and form.password.data == form.repeat_password.data:
        user = User(
            email=form.email.data, password=generate_password_hash(form.password.data),firstname=form.firstname.data, lastname=form.lastname.data, childname=form.childname.data
        )
        

        db.session.add(user)
        db.session.commit()

        return redirect(url_for("index"))

    return render_template("register.html", form=form)

@app.route("/pricing")
def pricing():
    return render_template("pricing.html")


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("index"))

@app.route("/dashboard")
@login_required
def dashbaord(): 
    return render_template("dashboard.html")






@app.route("/pictures/<filename>")
def pictures(filename):
    filename_full = "images/" + str(filename) + ".jpg"
    print(filename_full, flush=True)
    return send_from_directory('static', filename_full)

PIPENV_IGNORE_VIRTUALENVS=1
db.create_all()

if __name__ == "__main__":
    app.run(debug = True)



