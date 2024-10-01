from crypt import methods
from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
# Import your forms from the forms.py
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
# env variables
import os


# APP INI
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_KEY')
ckeditor = CKEditor(app)
Bootstrap5(app)

# TODO: Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def lead_user(user_id):
    return db.session.execute(db.select(User).where(User.id == user_id)).scalar()

# CREATE DATABASE
class Base(DeclarativeBase):
    pass
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DB_URI', 'sqlite:///posts.db')
db = SQLAlchemy(model_class=Base)
db.init_app(app)


# CONFIGURE TABLES
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    # author: Mapped[str] = mapped_column(String(250), nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)
    # Author ID bedzie mial id z user.id
    author_id: Mapped[int] = mapped_column(Integer, db.ForeignKey('users.id'))
    # relationship z tabelką User i przypiszemy mu posty (dziecko)
    author = relationship('User', back_populates='posts')
    # ojciec
    comments = relationship('Comment', back_populates='parent_post')


# TODO: Create a User table for all your registered users. 
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    # relationship z tabelką BlogPost i przypiszemy im autora (ojciec)
    posts = relationship('BlogPost', back_populates='author')
    # ojciec
    comments =  relationship('Comment', back_populates='comment_author')

# TABLE FOR COMMENTS
class Comment(db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    author_id : Mapped[int] = mapped_column(Integer, db.ForeignKey('users.id'))
    # dziecko
    comment_author = relationship('User', back_populates='comments')

    post_id : Mapped[int] = mapped_column(Integer, db.ForeignKey('blog_posts.id'))
    # dziecko
    parent_post = relationship('BlogPost', back_populates='comments')
    text: Mapped[str] = mapped_column(Text, nullable=False)
# DZIECI Z RELATIONSHIP OD DZIECKA TRZEBA PODAC PRZY TWORZENIU NOWEGO ELEMENTU W TABELCE


with app.app_context():
    db.create_all()

# OBRAZKI (losowe parametry ze strony)
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

# TODO: Use Werkzeug to hash the user's password when creating a new user.
@app.route('/register', methods=['POST', 'GET'])
def register():
    register_form = RegisterForm()
    if request.method == 'POST' and register_form.validate_on_submit():
        potential_user = db.session.execute(db.select(User).where(User.email == request.form['email'])).scalar()
        # checking if this email is already in db
        if potential_user:
            flash('This user already exists, log in instead.')
            return redirect(url_for('login'))
        # else - creating new user with hashed and salted pw
        else:
            hashed_and_salted_pw = generate_password_hash(password=request.form['password'],
                                                          method='pbkdf2:sha256',
                                                          salt_length=8)
            new_user = User(email=request.form['email'],
                            password=hashed_and_salted_pw,
                            name=request.form['name'])
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=register_form)


# TODO: Retrieve a user from the database based on their email. 
@app.route('/login', methods=['POST', 'GET'])
def login():
    login_form = LoginForm()
    if request.method == 'POST' and login_form.validate_on_submit():
        password = request.form['password']
        email = request.form['email']
        user = db.session.execute(db.select(User).where(User.email == email)).scalar()
        if user:
            # Checking if password matches
            if check_password_hash(pwhash=user.password, password=password):
                # Log in user
                login_user(user)
                return redirect(url_for('get_all_posts'))
            else:
                flash('Password is incorrect')
        else:
            flash('User with given email does not exist')
    return render_template("login.html", form=login_form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template("index.html", all_posts=posts)


# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>", methods=['POST', 'GET'])
def show_post(post_id):
    comment_form = CommentForm()
    requested_post = db.get_or_404(BlogPost, post_id)
    all_comments = db.session.execute(db.select(Comment).where(Comment.post_id == requested_post.id)).scalars().all()
    if request.method == 'POST' and comment_form.validate_on_submit():
        if current_user.is_authenticated:
            new_comment = Comment(text=request.form['body'], comment_author=current_user, parent_post=requested_post)
            db.session.add(new_comment)
            db.session.commit()
        else:
            return redirect(url_for('login'))
    return render_template("post.html", post=requested_post, form=comment_form, comments=all_comments)


# TODO: Use a decorator so only an admin user can create a new post
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        print(current_user.id)
        if current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function


@app.route("/new-post", methods=["GET", "POST"])
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
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


# TODO: Use a decorator so only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
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
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True)


# TODO: Use a decorator so only an admin user can delete a post
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
    app.run(debug=False, port=5002)
