from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import relationship
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
import os


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_KEY')
ckeditor = CKEditor(app)
Bootstrap5(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "get_all_posts"


# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DB_URI", "sqlite:///posts.db")
db = SQLAlchemy()
db.init_app(app)


gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


# CONFIGURE TABLES
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    author = db.Column(db.String(250), nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    comments = db.relationship("Comment", backref="comment_parent_post")


class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)
    posts = db.relationship("BlogPost", backref="user")
    comments = db.relationship("Comment", backref="comment_autor")


class Comment(db.Model, UserMixin):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    parent_post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    text = db.Column(db.Text, nullable=False)


def admin_only(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if current_user.is_authenticated and current_user.id == 1:
            return func(*args, **kwargs)
        else:
            return abort(code=403)
    return wrapper


@login_manager.user_loader
def load_user(user_id):
    return db.session.execute(db.select(User).where(User.id == user_id)).scalar()


@app.route(rule='/register', methods=["GET", "POST"])
def register():
    register_form = RegisterForm()
    if register_form.validate_on_submit():
        register_form_data = request.form.to_dict()

        user_db_data = (db.session.execute(db.select(User).where(User.email == register_form_data["email"])).
                        scalar())
        if user_db_data:
            flash(message="User with that email already exists!")
            return redirect(location=url_for(endpoint="login", email=user_db_data.email))
        new_user = User(email=register_form_data.get("email"),
                        password=generate_password_hash(register_form_data.get("password")),
                        name = register_form_data.get("name"))
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        new_db_user = (db.session.execute(db.select(User).where(User.email == register_form_data["email"])).
                       scalar())
        login_user(new_db_user)
        return redirect(location=url_for("get_all_posts"))
    return render_template(template_name_or_list="register.html", form=register_form)


@app.route(rule='/login', methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(location=url_for("get_all_posts"))

    login_form = LoginForm()

    if login_form.validate_on_submit():
        form_user_data = request.form.to_dict()
        db_user_data = db.session.execute(db.select(User).where(User.email == form_user_data["email"])).scalar()

        if not db_user_data:
            flash(message=f"E-mail {form_user_data['email']} is not in Database!")
            return redirect(location=url_for("login"))
        if check_password_hash(pwhash=db_user_data.password, password=form_user_data["password"]):
            login_user(db_user_data)
            print(f"User {db_user_data.email} has successfully logged in!")
            return redirect(location=url_for("get_all_posts"))
        else:
            flash("Password isn't correct! Try again.")
            return redirect(location=url_for(endpoint='login', email=form_user_data['email']))
    login_form.email.data = request.values.get("email")
    return render_template(template_name_or_list="login.html", form=login_form)


@app.route('/logout')
@login_required
def logout():
    print(f"User {current_user.email} has successfully logged out!")
    logout_user()
    redirect_url = request.values.get("url")
    return redirect(redirect_url)


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template(template_name_or_list="index.html", all_posts=posts)


@app.route(rule="/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = db.get_or_404(BlogPost, post_id)

    comment_form = CommentForm()
    if comment_form.validate_on_submit():
        if current_user.is_authenticated:
            new_comment = Comment(
                text=request.form.get('body'),
                comment_parent_post=requested_post,
                comment_autor=current_user
            )
            db.session.add(new_comment)
            db.session.commit()
            return redirect(location=url_for(endpoint="show_post", post_id=post_id))
        else:
            flash(message="You should be logged in to comment posts!")
            return redirect(location=url_for(endpoint="login"))
    return render_template(template_name_or_list="post.html", post=requested_post, form=comment_form)


@app.route(rule="/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user.name,
            date=date.today().strftime("%B %d, %Y"),
            user=current_user
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template(template_name_or_list="make-post.html", form=form)


@app.route(rule="/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user.name
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for(endpoint="show_post", post_id=post.id))
    return render_template(template_name_or_list="make-post.html", form=edit_form, is_edit=True)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


if __name__ == "__main__":
    app.run(debug=False)
