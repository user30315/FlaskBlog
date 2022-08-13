import os
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap
from datetime import date
from werkzeug.exceptions import abort
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from wtforms.validators import DataRequired, URL, Email
from forms import CreatePostForm
from flask_gravatar import Gravatar
from is_safe_url import is_safe_url
from flask_ckeditor import CKEditor, CKEditorField

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap(app)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL", "sqlite:///blog.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False,
                    base_url=None)


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    # author = db.Column(db.String(250), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    author = relationship("User", back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    post_comments = relationship("Comment", back_populates="parent_post")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    comment_author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    comment_author = relationship("User", back_populates="comments")
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    parent_post = relationship("BlogPost", back_populates="post_comments")
    text = db.Column(db.Text, nullable=False)


class CommentForm(FlaskForm):
    text = CKEditorField("Comment", validators=[DataRequired()])
    submit = SubmitField('Publish comment')


class RegisterForm(FlaskForm):
    name = StringField('Name:', validators=[DataRequired()])
    email = StringField('Email:', validators=[DataRequired(), Email()])
    password = PasswordField('Password:', validators=[DataRequired()])
    submit = SubmitField('Submit')


class LoginForm(FlaskForm):
    email = StringField('Email:', validators=[DataRequired(), Email()])
    password = PasswordField('Password:', validators=[DataRequired()])
    submit = SubmitField('Submit')


class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    author = StringField("Your Name", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


db.create_all()
db.session.commit()


def admin_only(func):
    def wrapper_func(*args, **kwargs):
        if current_user.is_authenticated and int(current_user.get_id()) == 1:
            return func(*args, **kwargs)
        else:
            return redirect(url_for("login"))

    wrapper_func.__name__ = func.__name__
    return wrapper_func


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts,
                           admin=(current_user.is_authenticated and int(current_user.get_id()) == 1))


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=request.form.get('email')).first():
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))
        else:
            user = User(email=request.form.get('email'), name=request.form.get('name'),
                        password=generate_password_hash(request.form.get('password'), method='pbkdf2:sha256',
                                                        salt_length=8))
            db.session.add(user)
            db.session.commit()
            login_user(user)
            return redirect(url_for("get_all_posts"))
            # if not is_safe_url(url_for("get_all_posts"),
            #                    allowed_hosts={"http://127.0.0.1:5000"}):
            #     flash('The page you were about to be redirected to is not safe.')
            #     return abort(400)
            # else:
            #     return redirect(url_for("get_all_posts"))
    return render_template("register.html", form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=request.form.get('email')).first():
            user = User.query.filter_by(email=request.form.get('email')).first()
            if check_password_hash(user.password, request.form.get('password')):
                login_user(user)
                return redirect(url_for("get_all_posts"))
                # if not is_safe_url(url_for("get_all_posts"), allowed_hosts={"http://127.0.0.1:5000"}):
                #     flash('The page you were about to be redirected to is not safe.')
                #     return abort(400)
                # else:
                #     return redirect(url_for("get_all_posts"))
            else:
                flash('Please, enter the right password.')
                return render_template("login.html", form=form)
        else:
            flash('This user does not exist, please sign up.')
            return redirect(url_for('register'))
    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    form = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    if form.validate_on_submit() and current_user.is_authenticated:
        db.session.add(Comment(comment_author_id=User.query.filter_by(name=current_user.name).first(),
                               comment_author=User.query.filter_by(name=current_user.name).first(),
                               post_id=BlogPost.query.get(post_id),
                               parent_post=BlogPost.query.get(post_id), text=form.text.data))
        db.session.commit()
        return redirect(url_for("show_post", form=CommentForm(), post_id=post_id,
                                admin=(current_user.is_authenticated and int(current_user.get_id()) == 1),
                                comments=requested_post.post_comments))
    elif form.validate_on_submit() and not current_user.is_authenticated:
        flash("You need to log in first!")
        return redirect(url_for('login'))
    return render_template("post.html", post=requested_post, form=form,
                           admin=(current_user.is_authenticated and int(current_user.get_id()) == 1),
                           comments=requested_post.post_comments)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        db.session.add(BlogPost(title=form.title.data, subtitle=form.subtitle.data, body=form.body.data,
                       img_url=form.img_url.data, author=current_user, date=date.today().strftime("%B %d, %Y")))
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(title=post.title, subtitle=post.subtitle, img_url=post.img_url, author=post.author,
                               body=post.body)
    if edit_form.validate_on_submit():
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", form=CommentForm(), post_id=post.id, comments=post.post_comments,
                                admin=(current_user.is_authenticated and int(current_user.get_id()) == 1)))
    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>", methods=["GET", "POST"])
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
