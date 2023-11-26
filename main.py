from werkzeug.security import generate_password_hash, check_password_hash
import email_validator
from time import sleep, time, strftime
import secrets 
from flask import Flask, render_template, redirect, url_for, flash, request, session, g, send_file, abort, jsonify
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, EqualTo, Email
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta, timezone
import threading
from threading import Lock
from flask_mail import Mail, Message
from smtplib import SMTP
import string
from os import getenv
from sqlite3 import connect
from time import time
from math import floor
from flask_socketio import SocketIO, emit
from base64 import b64decode
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

app = Flask('app')

socketio = SocketIO(app)

app.config['SECRET_KEY'] = 'VERY-IMPORTANT-KEY'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'skyboxcloud0@gmail.com'
app.config['MAIL_PASSWORD'] = getenv('EMAIL')
app.config['MAIL_DEFAULT_SENDER'] = 'skyboxcloud0@gmail.com'
app.secret_key = "VERY-IMPORTANT-KEY"

conn = connect('db.db',check_same_thread=False)
c = conn.cursor()

mail = Mail(app)

lock = Lock()

def dbs(s,t):
  lock.acquire(True)
  c.execute(s[0],s[1])
  conn.commit()
  if t:
    k = c.fetchall()
  else:
    k = c.fetchone()
  lock.release()
  return k
  

@app.route('/')
def home():
  if current_user.is_authenticated:
    user_agent = request.headers.get('User-Agent')
    user_agent = user_agent.lower()
    rooms = dbs(("SELECT Rooms FROM user WHERE User = (?)",(current_user.username,)),False)[0]
    print(rooms)
    if rooms == '' or rooms == None:
      rooms = ['main']
    else:
      rooms = (str(rooms)+'main').split(':')[::-1]
    if "iphone" in user_agent:
        return render_template('mobilemain.html', user=current_user.username, availablerooms=rooms)
    elif "android" in user_agent:
        return render_template('mobilemain.html', user=current_user.username, availablerooms=rooms)
    else:
      return render_template('main.html', user=current_user.username, availablerooms=rooms)
  else:
    return redirect('/login')

@app.route('/api/createroom',methods=['GET','POST'])
def createroom():
  try:
    if (request.headers.get('room'),) not in dbs((('SELECT Name FROM rooms'),()),True):
      #check if already has room with name
      dbs(("INSERT INTO rooms VALUES(?,?,?)",(request.headers.get('room'),request.headers.get('pwd'),request.headers.get('creator') + ':')),False)
      old = dbs(("SELECT Rooms FROM user WHERE User = (?)",(request.headers.get('creator'),)),False)[0]
      dbs(('UPDATE user SET Rooms = (?) WHERE User = (?)',(str(old) + request.headers.get('room') + ':', request.headers.get('creator'))),False)
      print('room created')
      return 'Room created!'
    else:
      print('room exists')
      return 'Room already exists!'
  except Exception as e:
    print(str(e))
    return 'fail: '+str(e)

@app.route('/api/joinroom',methods=['GET','POST'])
def joinroom():
  try:
    print('user is joining')
    if dbs(("SELECT Pwd FROM rooms WHERE Name = (?)",(request.headers.get('room'),)), False)[0] == request.headers.get('pwd'):
      print('Correct password!')
      new_room = request.headers.get('room') + ':'
      user = request.headers.get('user')
      existing_rooms = dbs(("SELECT Rooms FROM user WHERE User = (?)", (user,)), False)[0]
      if existing_rooms is None:
          existing_rooms = ''
      updated_rooms = existing_rooms + new_room
      dbs(('UPDATE user SET Rooms = (?) WHERE User = (?)', (updated_rooms, user)), False)
      current_users = dbs(('SELECT Users FROM rooms WHERE Name = (?)', (request.headers.get('room'),)), False)[0]
      new_users = current_users + request.headers.get('user') + ':'
      dbs(('UPDATE rooms SET Users = (?) WHERE Name = (?)', (new_users, request.headers.get('room'))), False)
      print('joined')
      return 'Joined!'
    else:
      print('wrong pass')
      return 'Wrong password'
  except Exception as e:
    print('error: '+str(e))
    return 'fail: '+str(e)

@app.route('/api/listroom/<user>',methods=['POST','GET'])
def retuserooms(user):
  try:
    rooms = dbs(("SELECT Rooms FROM user WHERE User = (?)",(user,)),False)[0]
    if rooms == '' or rooms == None:
      return ['main']
    else:
      rooms = (rooms+'main').split(':')[::-1]
    return rooms
  except Exception as e:
    return 'fail: '+str(e)

user_sids = {}
uname_to_sid = {}

@socketio.on('connect')
def handle_connect():
    print('please work')
    username = request.args.get('username')
    if username in list(uname_to_sid.keys()):
      print('multiple clients')
      socketio.emit('multipleClients', {'message': 'too many clients'}, room=request.sid)
    else:
      user_sids[request.sid] = username
      uname_to_sid[username] = request.sid
      print(f"{username} connected with sid {request.sid}")

@socketio.on('disconnect')
def handle_disconnect():
    print('disconnect')
    try:
      username = user_sids[request.sid]
      del user_sids[request.sid]
      del uname_to_sid[username]
      print(f'{username} {request.sid} disconnected')
    except Exception as e:
      print(str(e))

@socketio.event
def handle_transfer(data):
    print(data)
    username = data
    socketio.emit('multipleClients', {'message': 'too many clients'}, room=uname_to_sid[username])
    del user_sids[uname_to_sid[username]]
    del uname_to_sid[username]
    print(f"{username} disconnected for new client with sid {request.sid}")


@app.route('/api/send',methods=['POST'])
def send():
  r = floor(time())
  dbs(('INSERT INTO Msgs VALUES(?,?,?,?)',(request.headers['room'],request.headers['user'],request.headers['message'],r)),False)
  if request.headers['room'] == 'main':
    socketio.emit('new_message', {'room': request.headers['room'],'user':request.headers['user'],'message':request.headers['message'],'time':datetime.strftime(datetime.fromtimestamp(r,tz=timezone(timedelta(hours=-int(request.get_json()['timediff'])))),"%I:%M:%S %p %m/%d/%Y")})
    return 'success'
  n = dbs(('SELECT Users FROM rooms WHERE Name = (?)',(request.headers['room'],)),False)[0].split(':')[:-1]
  print(n)
  for i in n:
    try:
      socketio.emit('new_message', {'room': request.headers['room'],'user':request.headers['user'],'message':request.headers['message'],'time':datetime.strftime(datetime.fromtimestamp(r,tz=timezone(timedelta(hours=-int(request.get_json()['timediff'])))),"%I:%M:%S %p %m/%d/%Y")},room=uname_to_sid[i])
    except Exception as e:
      print(e)
  return 'success'

@app.route('/api/retrieve/<room>/',methods=["POST","GET"])
def retmessages(room):
  data = request.get_json()
  print(data)
  if data['start'] == 0:
    cr = dbs(('SELECT user,msg,time FROM Msgs WHERE room = (?) ORDER BY time DESC LIMIT 50',(room,)),True)
    for i in range(len(cr)):
      cr[i] = cr[i][0],cr[i][1],datetime.strftime(datetime.fromtimestamp(cr[i][2],tz=timezone(timedelta(hours=-int(data['timediff'])))),"%I:%M:%S %p %m/%d/%Y")
    return cr[::-1]
  else:
    cr = dbs(('SELECT user,msg,time FROM Msgs WHERE room = (?) ORDER BY time DESC LIMIT (?) OFFSET (?)',(room,50,int(data['start']))),True)
    for i in range(len(cr)):
      cr[i] = cr[i][0],cr[i][1],datetime.strftime(datetime.fromtimestamp(cr[i][2],tz=timezone(timedelta(hours=-int(data['timediff'])))),"%I:%M:%S %p %m/%d/%Y")
    if len(cr) == 0:
      return 'no'
    else:
      return cr[::-1]
    
    
  

@app.route('/api/count/<room>',methods=["GET","POST"])
def retcount(room):
  return str(dbs(('SELECT COUNT(*) FROM Msgs WHERE room = (?)',(room,)),False)[0])

@app.route('/api/rooms')
def re():
  return [i[0] for i in dbs(('SELECT * FROM rooms',()),True)]

def generate_verification_code():
    return ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(6))

@app.route('/key')
def ahahah():
  public_key = load_pem_public_key(b64decode(request.headers['key']))
  k = b'\xee\x00\x87\xfby\x8f\x01\x15\\\x1d\x08\xb1A~\x0c6\'">\x10\x05\xea\xe6fSD\x81\x9a\x0e|\xb4\xcb'
  n = b'\xd1\x88\x14\x9a\x95r\x7f\xa3E.Mp'
  public_key.encrypt(k,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None),)+n
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    email = db.Column(db.String(120), index=True, unique=True)
    email_sent_at = db.Column(db.DateTime)
    email_verified = db.Column(db.Boolean, default=False)
    email_verification_code = db.Column(db.String(6))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    password_reset_token = db.Column(db.String(64))
    password_reset_token_expiry = db.Column(db.DateTime)

    def __repr__(self):
        return '<User {}>'.format(self.username)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

def validate_email(email):
    user = User.query.filter_by(email=email.lower()).first()
    if user:
        return 'Email address already in use.'
    else:
      return "Success"

def validate_name(username):
    user = User.query.filter_by(username=username).first()
    if user:
        return 'username address already in use.'
    else:
      return "Success"

def send_verification_email(user):
    verification_code = generate_verification_code()
    message = Message('Verify your email', recipients=[user.email])
    message.body = f'Thank you for signing up. Your verification code is {verification_code}.'
    print(verification_code)
    mail.send(message)
    user.email_sent_at = datetime.utcnow()
    user.email_verified = False
    user.email_verification_code = verification_code
    db.session.commit()

def delete_unverified_accounts():
  with app.app_context():
    users = User.query.filter_by(email_verified=False).all()
    for user in users:
        try:
          if user.email_sent_at < datetime.utcnow() - timedelta(minutes=5):
              db.session.delete(user)
              db.session.commit()
        except:
          db.session.delete(user)

def run_every_five_seconds():
    while True:
        t = threading.Timer(5.0, delete_unverified_accounts)
        t.start()
        t.join()
threading.Thread(target=run_every_five_seconds).start()

class SignupForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    email = StringField('Email', validators=[InputRequired(), Email(message='Invalid email')])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80), EqualTo('confirm', message='Passwords must match')])
    confirm  = PasswordField('Confirm Password')
    submit   = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(max=15)])
    password = PasswordField('Password', validators=[InputRequired(), Length(max=80)])
    submit   = SubmitField('Log In')

class PasswordResetForm(FlaskForm):
    password = PasswordField('New Password', validators=[InputRequired(), Length(min=8, max=80), EqualTo('confirm', message='Passwords must match')])
    confirm = PasswordField('Confirm Password')
    submit = SubmitField('Reset')

class PasswordResetRequestForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email(message='Invalid email')])
    submit = SubmitField('Next')

@app.route('/logout', methods=['GET','POST'])
@login_required
def logout():
    logout_user()
    try:
      session.pop('fileviewkey')
    except:
      pass
    flash('You have been loggzed out.', 'success')
    return redirect('/')

@app.before_request
def before_request():
    g.user = current_user

@app.route('/login', methods=['GET','POST'])
def login():
    if current_user.is_authenticated:
      flash('To login to a different account, please sign out first.')
      return redirect('/')
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data) and user.email_verified:
            login_user(user)
            if request.args.get('filenext') != None:
              return redirect(f'/file/{request.args.get("filenext")}')
            return redirect('/')
        else:
            flash('Invalid username or password.')
    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET','POST'])
def signup():
    if current_user.is_authenticated:
      flash('To signup, please sign out of your current account first.')
      return redirect('/')
    form = SignupForm()
    if form.validate_on_submit():
        email = form.email.data.lower()
        username = form.username.data
        if 'anonymous' in username.lower() or '\n' in username.lower() or '/' in username.lower() or '\\' in username.lower():
          flash('Cannot use this username')
        elif not (validate_email(email) == "Success"):
          flash('Email already in use')
        elif not (validate_name(username) == "Success"):
          flash('Username already in use')
        else:
          user = User(username=form.username.data, email=form.email.data.lower())
          user.set_password(form.password.data)
          db.session.add(user)
          db.session.commit()
          send_verification_email(user)
          return redirect(url_for('verify', username=form.username.data))
    return render_template('signup.html', form=form)

@app.route('/verify/<username>', methods=['GET','POST'])
def verify(username):
    user = User.query.filter_by(username=username).first_or_404() 
    if user.email_verified:
        flash('Your account has already been verified. Please log in.')
        return redirect(url_for('login'))
    if request.method == 'POST':
        if request.form['verification_code'] == user.email_verification_code:
            user.email_verified = True
            db.session.commit()
            flash('Your account has been verified. Please log in.')
            dbs(('INSERT INTO user VALUES(?,?)',(username,'')),False)
            return redirect(url_for('login'))
        else:
            flash('Invalid verification code. Please try again.')
    else:
        if user.email_sent_at < datetime.utcnow() - timedelta(minutes=5):
            db.session.delete(user)
            db.session.commit()
            flash('Your account has been deleted due to unauthentication of your email for more than 5 minutes.')
            return redirect(url_for('signup'))
    return render_template('verify.html', username=username)

with app.app_context():
    db.create_all()
socketio.run(app, host='0.0.0.0')
