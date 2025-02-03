from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FileField, TextAreaField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError
import random
import string
from datetime import datetime
from werkzeug.utils import secure_filename
import os
from PIL import Image
import bcrypt
from flask_mail import Mail, Message
from flask_socketio import SocketIO, emit

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///forum.db'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'xg.studio0302@gmail.com'
app.config['MAIL_PASSWORD'] = 'tjvyqxxmfoosaydr'  # 非邮箱登录密码
db = SQLAlchemy(app)
mail = Mail(app)
socketio = SocketIO(app)

# ---------- 数据库模型 ----------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    avatar = db.Column(db.String(120), default='default_avatar.png')
    posts = db.relationship('Post', backref='author', lazy=True)
    replies = db.relationship('Reply', backref='author', lazy=True)
    likes = db.relationship('Like', backref='user', lazy=True)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    replies = db.relationship('Reply', backref='post', lazy=True)
    likes = db.relationship('Like', backref='post', lazy=True)

class Reply(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)

class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)

# ---------- 表单类 ----------
class LoginForm(FlaskForm):
    username = StringField('您的用户名~', validators=[DataRequired()])
    password = PasswordField('您的密码~', validators=[DataRequired()])
    submit = SubmitField('登录哦~')

class RegisterForm(FlaskForm):
    username = StringField('您的用户名~', validators=[DataRequired()])
    email = StringField('您的邮箱~', validators=[DataRequired(), Email()])
    password = PasswordField('您的密码~', validators=[DataRequired()])
    confirm_password = PasswordField('确认密码一下，谢谢！！！', validators=[DataRequired(), EqualTo('password')])
    avatar = FileField('请上传头像哦~')
    submit = SubmitField('注册哦~')

    def validate_password(self, field):
        password = field.data
        if len(password) < 8:
            raise ValidationError('密码至少8位呢~')
        if not any(c.isdigit() for c in password):
            raise ValidationError('密码需包含数字呢~')
        if not any(c.isalpha() for c in password):
            raise ValidationError('密码需包含字母呢~')

class PostForm(FlaskForm):
    title = StringField('请您输入标题哦~', validators=[DataRequired()])
    content = TextAreaField('请您输入内容哦~', validators=[DataRequired()])
    submit = SubmitField('3.2.1~发布！！！')

# ---------- 工具函数 ----------
def generate_verification_code():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=6))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def save_uploaded_file(file):
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        img = Image.open(filepath)
        img.thumbnail((200, 200))
        img.save(filepath)
        return filename
    return None

def send_verification_email(email, code):
    msg = Message(
        subject='ACG-MCBBSの邮箱验证码',
        sender=app.config['MAIL_USERNAME'],
        recipients=[email]
    )
    msg.body = f'您好，感谢注册ACG-MCBBS！您的验证码是：{code}（有效期5分钟哦）'
    mail.send(msg)
# ---------- 路由逻辑 ----------
@app.route('/')
def index():
    posts = Post.query.order_by(Post.date_posted.desc()).all()
    return render_template('index.html', posts=posts)

@app.route('/post/<int:post_id>')
def view_post(post_id):
    post = Post.query.get_or_404(post_id)
    replies = Reply.query.filter_by(post_id=post_id).order_by(Reply.date_posted.desc()).all()
    likes = Like.query.filter_by(post_id=post_id).count()
    return render_template('view_post.html', post=post, replies=replies, likes=likes)

@app.route('/post/<int:post_id>/reply', methods=['POST'])
def reply_post(post_id):
    if 'user_id' not in session:
        flash('请先登录呢！', 'danger')
        return redirect(url_for('login'))
    content = request.form.get('content')
    if content:
        reply = Reply(content=content, user_id=session['user_id'], post_id=post_id)
        db.session.add(reply)
        db.session.commit()
        flash('回复成功哦！', 'success')
    else:
        flash('回复内容不能为空呀！', 'danger')
    return redirect(url_for('view_post', post_id=post_id))

@app.route('/post/<int:post_id>/like', methods=['POST'])
def like_post(post_id):
    if 'user_id' not in session:
        flash('请先登录呢！', 'danger')
        return redirect(url_for('login'))
    user_id = session['user_id']
    like = Like.query.filter_by(user_id=user_id, post_id=post_id).first()
    if like:
        db.session.delete(like)
        db.session.commit()
        flash('取消点赞~', 'info')
    else:
        like = Like(user_id=user_id, post_id=post_id)
        db.session.add(like)
        db.session.commit()
        flash('点赞成功呢！', 'success')
    return redirect(url_for('view_post', post_id=post_id))

@app.route('/admin')
def admin():
    if 'user_id' not in session:
        flash('请先登录呢！', 'danger')
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if user.username != 'admin':
        flash('您没有权限访问此页面哦！', 'danger')
        return redirect(url_for('index'))
    posts = Post.query.order_by(Post.date_posted.desc()).all()
    users = User.query.all()
    return render_template('admin.html', posts=posts, users=users)

@app.route('/admin/delete_post/<int:post_id>', methods=['POST'])
def delete_post(post_id):
    if 'user_id' not in session:
        flash('请先登录呢！', 'danger')
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if user.username != 'admin':
        flash('您没有权限执行此操作哦！', 'danger')
        return redirect(url_for('index'))
    post = Post.query.get_or_404(post_id)
    db.session.delete(post)
    db.session.commit()
    flash('帖子已删除！忘了我叭呜呜呜~~~', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if 'user_id' not in session:
        flash('请先登录呢！', 'danger')
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if user.username != 'admin':
        flash('您没有权限执行此操作哦！', 'danger')
        return redirect(url_for('index'))
    user_to_delete = User.query.get_or_404(user_id)
    db.session.delete(user_to_delete)
    db.session.commit()
    flash('用户已删除！！！小心行事呢！', 'success')
    return redirect(url_for('admin'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.checkpw(form.password.data.encode('utf-8'), user.password.encode('utf-8')):
            session['user_id'] = user.id
            session['username'] = user.username
            flash('登录成功哦！', 'success')
            return redirect(url_for('index'))
        else:
            flash('用户名或密码错误哦！', 'danger')
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash('该邮箱已被注册呢！换个叭！', 'danger')
            return redirect(url_for('register'))

        avatar_filename = save_uploaded_file(form.avatar.data)
        if not avatar_filename:
            flash('文件上传失败呢，请上传PNG、JPG或GIF格式的图片哦！', 'danger')
            return redirect(url_for('register'))

        verification_code = generate_verification_code()
        send_verification_email(form.email.data, verification_code)

        session['verification_info'] = {
            'code': verification_code,
            'expiry': datetime.now().timestamp() + 300,
            'username': form.username.data,
            'email': form.email.data,
            'password': bcrypt.hashpw(form.password.data.encode('utf-8'), bcrypt.gensalt()).decode('utf-8'),
            'avatar': avatar_filename
        }
        flash('验证码已发送至您的邮箱哦，请查收哦！！！', 'info')
        return redirect(url_for('verify_email'))
    return render_template('register.html', form=form)

@app.route('/verify_email', methods=['GET', 'POST'])
def verify_email():
    if request.method == 'POST':
        verification_info = session.get('verification_info')
        if not verification_info or datetime.now().timestamp() > verification_info['expiry']:
            flash('验证码已过期哦，请重新注册叭', 'danger')
            return redirect(url_for('register'))

        if request.form['verification_code'] == verification_info['code']:
            new_user = User(
                username=verification_info['username'],
                email=verification_info['email'],
                password=verification_info['password'],
                avatar=verification_info['avatar']
            )
            db.session.add(new_user)
            db.session.commit()
            session.pop('verification_info')
            flash('注册成功呀！请登录哦！！！', 'success')
            return redirect(url_for('login'))
        else:
            flash('验证码错误哦，请重新逝逝叭', 'danger')
    return render_template('verify_email.html')

@app.route('/resend_code')
def resend_code():
    verification_info = session.get('verification_info')
    if verification_info:
        send_verification_email(verification_info['email'], verification_info['code'])
        flash('验证码已重新发送哦！', 'info')
    else:
        flash('请先填写注册信息呢！', 'danger')
    return redirect(url_for('verify_email'))

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        flash('请先登录呢！', 'danger')
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    return render_template('profile.html', user=user)

@app.route('/post/new', methods=['GET', 'POST'])
def new_post():
    if 'user_id' not in session:
        flash('请先登录呢！', 'danger')
        return redirect(url_for('login'))
    form = PostForm()
    if form.validate_on_submit():
        post = Post(title=form.title.data, content=form.content.data, user_id=session['user_id'])
        db.session.add(post)
        db.session.commit()
        flash('帖子发布成功哦！谢谢您的付出！', 'success')
        return redirect(url_for('index'))
    return render_template('post.html', form=form)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/logout')
def logout():
    session.clear()
    flash('您已退出登录呢！欢迎下次再次登录哦！', 'info')
    return redirect(url_for('index'))

# ---------- SocketIO 事件处理 ----------
@socketio.on('send_message')
def handle_send_message(data):
    """处理用户发送的消息"""
    username = session.get('username', '匿名用户')
    message = data['message']
    emit('receive_message', {'username': username, 'message': message}, broadcast=True)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    socketio.run(app, debug=True)  # 使用SocketIO运行应用