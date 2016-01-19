#!/usr/bin/python3
# -*- coding:utf-8 -*-

from app import app, db, lm, oid
from flask import render_template, flash, redirect, session, url_for, request, g
from time import gmtime, strftime
from app.forms import LoginForm
from flask.ext.login import login_user, logout_user, current_user, login_required
from app.models import User, ROLE_USER, ROLE_ADMIN
import subprocess

@app.route('/')
@app.route('/index')
def index():
    user = g.user
    posts = [ # fake posts
        {
            'author': { 'nickname':'John' },
            'body':'Beautiful day in Portland!'
        },
        {
            'author': { 'nickname':'Susan' },
            'body':'The Avengers movie was so cool!'
        },
        {
            'author': { 'nickname':'Vovan' },
            'body':'A yli delat ???'
        }
    ]
    return render_template("index.html",
                           title = 'Home',
                           user = user,
                           posts = posts)

@app.route('/user/<nickname>')
@login_required
def user(nickname):
    user = User.query.filter_by(nickname = nickname).first()
    if user == None:
        flash('User %s not found.' % nickname)
        return redirect(url_for('index'))
    posts = [
        { 'author': user, 'body': 'Test post #1' },
        { 'author': user, 'body': 'Test post #2' }
    ]
    return render_template('user.html',
        user = user,
        posts = posts)


@app.before_request
def before_request():
    g.user = current_user

@lm.user_loader
def load_user(id):
    return User.query.get(int(id))

@app.route('/login', methods=['GET', 'POST'] )
@oid.loginhandler
@oid.loginhandler
def login():
    if g.user is not None and g.user.is_authenticated:
      return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        session['remember_me'] = form.remember_me.data
        return oid.try_login(form.openid.data, ask_for = ['nickname', 'email'])
    return render_template('login.html',
                           title = 'Sign In',
                           form = form,
                           providers = app.config['OPENID_PROVIDERS'])

@oid.after_login
def after_login(resp):
    if resp.email is None or resp.email == "":
        flash('Invalid login. Please try again.')
        return redirect(url_for('login'))
    user = User.query.filter_by(email = resp.email).first()
    if user is None:
        nickname = resp.nickname
        if nickname is None or nickname == "":
            nickname = resp.email.split('@')[0]
        user = User(nickname = nickname, email = resp.email, role = ROLE_USER)
        db.session.add(user)
        db.session.commit()
    remember_me = False
    if 'remember_me' in session:
        remember_me = session['remember_me']
        session.pop('remember_me', None)
    login_user(user, remember = remember_me)
    return redirect(request.args.get('next') or url_for('index'))

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))



@app.route('/time')
@login_required
def datetime():
    dt= strftime("%a, %d %b %Y %H:%M:%S +0000", gmtime())
    return render_template('time.html',
                           title= 'Time',
                           date = dt,
                           commands = AVAILABLE_COMMANDS)


LEFT, RIGHT, UP, DOWN, RESET = "left", "right", "up", "down", "reset"
AVAILABLE_COMMANDS = {
    'Left': LEFT,
    'Right': RIGHT,
    'Up': UP,
    'Down': DOWN,
    'Reset': RESET
}

@app.route('/<cmd>')
def command(cmd=None):
    if cmd == RESET:
        print('Reset')
        camera_command = "X"
        response = "Resetting ..."
    else:
        print('ELSE')
        camera_command = cmd[0].upper()
        response = "Moving {}".format(cmd.capitalize())

    # ser.write(camera_command)
    return response, 200, {'Content-Type': 'text/plain'}

















