from flask import Flask, render_template, redirect, url_for, flash, abort, request
from flask_bootstrap import Bootstrap4
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, UserRegisterForm, Login, CommentForm
from functools import wraps
from dotenv import load_dotenv
import os

# Load variables from .env file
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
ckeditor = CKEditor(app)
Bootstrap4(app)

# Connect to db
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# configure tables
####################################################################
class User(UserMixin, db.Model):
    __tablename__ = 'Users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), nullable=False)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)
    profile_img = db.Column(db.String(250), nullable=True)
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship('Comment', back_populates='author')


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("Users.id"))
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    author = relationship("User", back_populates="posts")
    comments = relationship('Comment', back_populates='parent_post')


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("Users.id"))
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    text = db.Column(db.Text, nullable=False)
    author = relationship('User', back_populates='comments')
    parent_post = relationship('BlogPost', back_populates='comments')


######################################################################

# Configure login manager
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.login_message = 'Invalid. Please login in to access that page.'
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, user_id)


# --- Admin only decorator --- #
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If id is not 1, then return abort with 403 error
        if not current_user.is_authenticated or current_user.id != 1:
            return abort(403)
        # Otherwise continue with the route function
        return f(*args, **kwargs)

    return decorated_function


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=['GET', 'POST'])
def register():
    user_registration_form = UserRegisterForm()
    if user_registration_form.validate_on_submit():
        email = user_registration_form.email.data
        password = user_registration_form.password.data
        name = user_registration_form.name.data
        img_url = 'https://picsum.photos/600/400'
        user_data = User.query.filter_by(email=email).first()
        # Checks if the email is not in the database and creates a new user if that's the case
        if user_data is None:
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
            new_user = User(email=email, name=name, password=hashed_password, profile_img=img_url)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)

            return redirect(url_for('get_all_posts'))
        else:
            flash("That email is already in use. Please try with a different one or login.")
            return render_template("register.html", form=user_registration_form)

    return render_template("register.html", form=user_registration_form)


@app.route('/login', methods=['POST', 'GET'])
def login():
    form = Login()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()
        # Checks if email is registered in the database
        if user is None:
            flash("The email does not exists. Maybe you meant register?")
            return render_template("login.html", form=form)
        else:
            if check_password_hash(pwhash=user.password, password=password):
                login_user(user, remember=True)
                return redirect(url_for('get_all_posts'))
            else:
                flash('Password incorrect. Please try again.')
                return redirect(url_for('login'))

    return render_template("login.html", form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    form = CommentForm()
    requested_post = db.session.get(BlogPost, post_id)
    if form.validate_on_submit():
        # Checks if the current user is logged in and lets they make a comment if that's the case
        if current_user.is_authenticated:
            new_comment = Comment(
                text=form.body.data,
                author=current_user,
                parent_post=requested_post,
            )
            db.session.add(new_comment)
            db.session.commit()
            return render_template("post.html", post=requested_post, form=form)
        else:
            flash('Sorry, only registered users can make comments.')
            return render_template("post.html", post=requested_post, form=form)

    return render_template("post.html", post=requested_post, form=form)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=['POST', 'GET'])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y"),
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=['POST', 'GET'])
@admin_only
def edit_post(post_id):
    post = db.session.get(BlogPost, post_id)
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
        post.body = edit_form.body.data
        post.author = current_user
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.session.get(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/delete/comment/<int:author_id>")
@admin_only
def delete_comment(author_id):
    comment_to_delete = Comment.query.filter_by(author_id=author_id).first()
    db.session.delete(comment_to_delete)
    db.session.commit()

    # Returns to post
    post_id = request.args.get('post_id')
    return redirect(url_for('show_post', post_id=post_id))


if __name__ == "__main__":
    app.run(debug=True)
