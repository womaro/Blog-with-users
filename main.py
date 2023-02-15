from flask import Flask, render_template, redirect, url_for, flash, request
from flask_wtf import FlaskForm
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from wtforms import PasswordField, SubmitField
from forms import CreatePostForm, RegisterForn, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps
import email_validator

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)


##CONFIGURE TABLES


class Users(UserMixin, db.Model):
    __tablename__ = "registered_users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), nullable=False, unique=True)
    password = db.Column(db.String(500), unique=True, nullable=False)
    posts = relationship('BlogPost', back_populates="post_author")
    comments = relationship('Comment', back_populates="comment_author")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('registered_users.id'))
    author = db.Column(db.String(250), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    post_author = relationship("Users", back_populates="posts")
    comment = relationship('Comment', back_populates="blog_post")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    # *******Add child relationship*******#
    # "users.id" The users refers to the tablename of the Users class.
    # "comments" refers to the comments property in the User class.
    user_id = db.Column(db.Integer, db.ForeignKey("registered_users.id"))
    comment_author = relationship("Users", back_populates="comments")
    blog_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    blog_post = relationship("BlogPost", back_populates="comment")


db.create_all()

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


def return_404():
    return render_template('404.html'), 404


def admin_only(function):
    @wraps(function)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.id != 1:
            return render_template('404.html'), 404
        else:
            print("admin")
            return function(*args, **kwargs)

    return decorated_function


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


@app.route('/')
def get_all_posts():
    if current_user.is_authenticated:
        logged = True
    else:
        logged = False
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, logged_in=logged)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForn()
    if form.validate_on_submit():
        db_user = Users.query.filter_by(email=form.email.data).first()
        if db_user is None:
            new_user = Users(
                email=form.email.data,
                password=generate_password_hash(password=form.password.data, method="pbkdf2:sha256", salt_length=10)
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('get_all_posts'))
        else:
            flash("User already exists. Try to log in instead.")
            return redirect(url_for('login'))
    return render_template("register.html", form=form)


@app.route('/login', methods=["POST", "GET"])
def login():
    form = LoginForm()
    is_admin = False
    if form.validate_on_submit():
        user = form.email.data
        passwd = form.password.data
        db_user = Users.query.filter_by(email=user).first()
        if db_user is None:
            flash("User does not exists. Please retry or register.")
            return redirect(url_for('login'))
        else:
            passwd_check = check_password_hash(db_user.password, passwd)
            if db_user.email == user and passwd_check:
                login_user(db_user)
                return redirect(url_for('get_all_posts'))
            else:
                flash("Incorrect password, please try again.")
                return redirect(url_for('login'))

    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["POST", "GET"])
def show_post(post_id):
    form = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    comments = Comment.query.filter_by(blog_id=post_id).all()
    if not current_user.is_authenticated:
        logged_in = False
    else:
        logged_in = True
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("In order to make comments, please register and log in first.")
            return redirect(url_for('login'))
        else:
            new_comment = Comment(
                user_id=current_user.id,
                text=form.comment.data,
                blog_id=post_id
            )
            db.session.add(new_comment)
            db.session.commit()
    return render_template("post.html", post=requested_post, form=form, comments=comments, logged_in=logged_in)




    #return render_template("post.html", post=requested_post, form=form, comments=comments, logged_in=logged_in)


@app.route("/about")
def about():
    if current_user.is_authenticated:
        logged = True
    else:
        logged = False
    return render_template("about.html", logged_in=logged)


@app.route("/contact")
def contact():
    if current_user.is_authenticated:
        logged = True
    else:
        logged = False
    return render_template("contact.html", logged_in=logged)


@app.route("/new-post", methods=["POST", "GET"])
@admin_only
def add_new_post():
    if current_user.is_authenticated:
        logged = True
    else:
        logged = False
    blogger = current_user.id
    print(blogger)
    form = CreatePostForm()
    if form.validate_on_submit():
        print(current_user.id)
        new_post = BlogPost(
            user_id=blogger,
            author=current_user.email,
            title=form.title.data,
            subtitle=form.subtitle.data,
            date=date.today().strftime("%B %d, %Y"),
            body=form.body.data,
            img_url=form.img_url.data
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, logged_in=logged)


@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
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
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    print(post_id)
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run()
