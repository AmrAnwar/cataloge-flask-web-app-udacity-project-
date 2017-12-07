from model import Base, User
from flask import Flask, jsonify, request, url_for, abort, g, render_template, flash, redirect
from sqlalchemy.orm import relationship, sessionmaker, scoped_session
from sqlalchemy import create_engine
from flask import session as login_session

import json

# NEW IMPORTS
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
from flask import make_response
import requests


from wtforms import StringField, SubmitField, TextField, FieldList, SelectField
from wtforms.validators import Required

from flask_httpauth import HTTPBasicAuth

from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm

from model import Category, Item, Base, User
import random
import string

auth = HTTPBasicAuth()

engine = create_engine('sqlite:///usersWithOAuth.db')

Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = scoped_session(DBSession)

app = Flask(__name__)
bootstrap = Bootstrap(app)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']


class NameForm(FlaskForm):
    categories = session.query(Category).all()

    title = StringField('title', validators=[Required()])
    description = StringField('description')
    category = SelectField(
        'Category',
        # choices=[('cpp', 'C++'), ('py', 'Python'), ('text', 'Plain Text')]
        choices=[(category.id, str(category.name)) for category in categories]
    )
    submit = SubmitField('Submit')


@app.route('/additem', methods=['GET', 'POST'])
def add_item():
    form = NameForm()
    if form.title and form.description.data and form.category.data:
        title = form.title.data
        description = form.description.data
        category_id = form.category.data
        new_item = Item(title=title,
                        description=description,
                        category_id=category_id,)
        session.add(new_item)
        session.commit()
        flash("new item was added")
        return redirect(url_for('index'))

    return render_template('form.html', form=form)


# JSON APIs to view Restaurant Information
@app.route('/<string:category_string>')
def category_items(category_string):
    category = session.query(Category).filter_by(name=category_string).one()
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for _ in xrange(32))
    login_session['state'] = state
    items = session.query(Item).filter_by(id=category.id).all()
    return render_template('index.html',
                           STATE=state,
                           title=category.name,
                           items=items)


# JSON APIs to view Restaurant Information
@app.route('/<string:category_string>/<string:item_string>')
def item_detail(category_string, item_string):
    item = session.query(Item).filter_by(title=item_string).one()
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for _ in xrange(32))
    login_session['state'] = state
    return render_template('item.html',
                           STATE=state,
                           title=item.title,
                           item=item)


@app.route('/<string:category_string>/<string:item_string>/edit')
def item_edit(category_string, item_string):
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for _ in xrange(32))
    login_session['state'] = state

    item = session.query(Item).filter_by(title=item_string).one()
    form = NameForm()
    form.title.data = item.title
    form.description.data = item.description
    form.category.data = item.category.name


    return render_template('form.html',
                           STATE=state,
                           title=item.title,
                           form=form)


@app.route('/<string:category_string>/<string:item_string>/delete')
def item_delete(category_string, item_string):
    item = session.query(Item).filter_by(title=item_string).one()
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for _ in xrange(32))
    login_session['state'] = state
    return render_template('item.html',
                           STATE=state,
                           title=item.title,
                           item=item)



@app.route('/', methods=['GET', 'POST'])
def index():

    categories = session.query(Category).all()
    items = session.query(Item).order_by("id desc").limit(10)
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for _ in xrange(32))
    login_session['state'] = state
    title = None
    form = NameForm()
    if form.validate_on_submit():
        title = form.title.data
    return render_template('index.html',
                           form=form,
                           title=title,
                           STATE=state,
                           categories=categories,
                           items=items)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    print request.args.get('state')
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    name = data['name']
    picture = data['picture']
    email = data['email']

    # see if user exists, if it doesn't make a new one
    user = session.query(User).filter_by(email=email).first()
    if not user:
        user = User(username=name, picture=picture, email=email)
        session.add(user)
        session.commit()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output


@app.route('/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token()
    return jsonify({'token': token.decode('ascii')})


@app.route('/users', methods=['POST'])
def new_user():
    username = request.json.get('username')
    password = request.json.get('password')
    if username is None or password is None:
        print "missing arguments"
        abort(400)

    if session.query(User).filter_by(username=username).first() is not None:
        print "existing user"
        user = session.query(User).filter_by(username=username).first()
        return jsonify({
                           'message': 'user already exists'}), 200  # , {'Location': url_for('get_user', id = user.id, _external = True)}

    user = User(username=username)
    user.hash_password(password)
    session.add(user)
    session.commit()
    return jsonify(
        {'username': user.username}), 201  # , {'Location': url_for('get_user', id = user.id, _external = True)}


@app.route('/api/users/<int:id>')
def get_user(id):
    user = session.query(User).filter_by(id=id).one()
    if not user:
        abort(400)
    return jsonify({'username': user.username})


@app.route('/api/resource')
@auth.login_required
def get_resource():
    return jsonify({'data': 'Hello, %s!' % g.user.username})


@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        print 'Access Token is None'
        response = make_response(json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    print 'In gdisconnect access token is %s', access_token
    print 'User name is: '
    print login_session['username']
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print 'result is '
    print result
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.debug = True
    app.secret_key = 'szvszvszvsbert4etbRGWYy$^#$'
    app.run(host='0.0.0.0', port=5000)
