import json
import random
import string
# to create the decorator
from functools import wraps

import httplib2
import requests
from flask import Flask, jsonify, request, url_for, abort, g, render_template, flash, redirect
from flask import make_response
from flask import session as login_session
from flask_bootstrap import Bootstrap
from flask_httpauth import HTTPBasicAuth
from flask_wtf import FlaskForm
from oauth2client.client import FlowExchangeError
from oauth2client.client import flow_from_clientsecrets
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from wtforms import StringField, SubmitField, SelectField
from wtforms.validators import Required

from model import Category, Item, Base, User

auth = HTTPBasicAuth()

engine = create_engine('sqlite:///usersWithOAuth.db')

Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = scoped_session(DBSession)

app = Flask(__name__)
bootstrap = Bootstrap(app)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']


def login_required(f):
    """
    check function tool library
    """

    @wraps(f)
    def wrapper(*args, **kwargs):
        if not ("username" in login_session):
            flash("you are not login please login first to add items")
            return redirect('/')
        return f(*args, **kwargs)

    return wrapper


class ItemForm(FlaskForm):
    """
    Form for add and edit items
    """
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
@login_required
def add_item():
    """
    add new item using ItemForm
    """
    form = ItemForm()
    user = session.query(User).filter_by(username=login_session['username']).one()
    if form.title and form.description.data and form.category.data:
        title = form.title.data
        description = form.description.data
        category_id = form.category.data
        new_item = Item(title=title,
                        description=description,
                        category_id=category_id,
                        user_id=user.id)
        session.add(new_item)
        session.commit()
        flash("new item was added")
        return redirect(url_for('index'))

    return render_template('form.html', form=form)


@app.route('/<string:category_string>')
def category_items(category_string):
    """
    get items for each category
    """
    category = session.query(Category).filter_by(name=category_string).first()
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for _ in xrange(32))
    login_session['state'] = state
    items = session.query(Item).filter_by(category_id=category.id).all()
    return render_template('index.html',
                           STATE=state,
                           title=category.name,
                           items=items)


@app.route('/<string:category_string>/<string:item_string>')
def item_detail(category_string, item_string):
    """
    get single item data and render it

    """
    item = session.query(Item).filter_by(title=item_string).one()
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for _ in xrange(32))
    login_session['state'] = state
    return render_template('item.html',
                           STATE=state,
                           title=item.title,
                           item=item)


@app.route('/<string:category_string>/<string:item_string>/edit', methods=['POST', 'GET', 'PUT'])
@login_required
def item_edit(category_string, item_string):
    """
    edit item using ItemForm and render it to edit
    """
    form = ItemForm()
    item = session.query(Item).filter_by(title=item_string).one()
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for _ in xrange(32))
    login_session['state'] = state

    if login_session['username'] != item.user.username:
        flash("you can't edit this item")
        return redirect("%s/%s" % (category_string, item_string))

    elif request.method == 'POST':
        # update data
        new_title = form.title.data
        if not session.query(Item).filter_by(title=new_title).first() or form.title.data == item.title:
            item.title = form.title.data
            item.description = form.description.data
            category = session.query(Category).filter_by(id=form.category.data).one()
            item.category = category
            session.commit()
            flash("element wad updated")
        else:
            flash("their are title with the same name")

    form.category.default = item.category.id
    form.process()
    form.title.data = item.title
    form.description.data = item.description

    return render_template('form.html',
                           STATE=state,
                           title=item.title,
                           form=form)


@app.route('/<string:category_string>/<string:item_string>/delete')
@login_required
def item_delete(category_string, item_string):
    """
    delete item run after Jquery user confirm Form
    """
    item = session.query(Item).filter_by(title=item_string).one()
    if login_session['username'] != item.user.username:
        flash("you can't delete this item")
        return redirect("%s/%s" % (category_string, item_string))
    session.delete(item)
    session.commit()
    if item is None:
        flash("element was not found")
    flash("element wad deleted")
    return redirect('/')


@app.route('/', methods=['GET', 'POST'])
def index():
    """
    Home Page get items and render it
    """
    categories = session.query(Category).all()
    items = session.query(Item).order_by("id desc").limit(10)
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for _ in xrange(32))
    login_session['state'] = state
    title = None
    form = ItemForm()
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
            'message': 'user already exists'}), 200

    user = User(username=username)
    user.hash_password(password)
    session.add(user)
    session.commit()
    return jsonify(
        {'username': user.username}), 201


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


# JSON DATA


@app.route('/<string:category_string>/<string:item_string>/JSON')
def item_detail_json(category_string, item_string):
    """
    get json data for a single item
    """
    item = session.query(Item).filter_by(title=item_string).one()
    return jsonify(item=[item.serialize])


@app.route('/<string:category_string>/JSON')
def category_items_json(category_string):
    """
    get json data for items in single category
    """
    category = session.query(Category).filter_by(name=category_string).first()
    items = session.query(Item).filter_by(category_id=category.id).all()
    return jsonify(items=[i.serialize for i in items])


@app.route('/JSON')
def index_json():
    """
    render all the items in json format
    """
    items = session.query(Item).all()
    return jsonify(items=[i.serialize for i in items if i.category])


if __name__ == '__main__':
    app.debug = True
    app.secret_key = 'szvszvszvsbert4etbRGWYy$^#$'
    app.run(host='127.0.0.1', port=5000)
