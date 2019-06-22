#!/usr/bin/env python3

from flask import Flask, render_template, redirect, url_for
from flask import request, flash, jsonify, abort, g
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from catalogdb import Base, Category, CategoryItem, User
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests
from flask_httpauth import HTTPBasicAuth

auth = HTTPBasicAuth()

app = Flask(__name__)
engine = create_engine('postgresql://catalog:123qweasd@localhost/catalog.db')
Base.metadata.bind = engine

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Catalog Application"


# Create anti-forgery state token
@app.route('/login')
def showLogin():
    DBSession = sessionmaker(bind=engine)
    session = DBSession()    
    if 'username' in login_session:
        return redirect(url_for('showCategories'))
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


@app.route('/users', methods=['POST'])
def new_user():
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    username = request.json.get('username')
    password = request.json.get('password')
    if username is None or password is None:
        print("missing arguments")
        abort(400)
    if session.query(User).filter_by(name=username).first() is not None:
        print("existing user")
        user = session.query(User).filter_by(name=username).first()
        return jsonify({'message': 'user already exists'}), 200
        # , {'Location': url_for('get_user', id = user.id, _external = True)}
    user = User(name=username)
    user.hash_password(password)
    session.add(user)
    session.commit()
    return jsonify({'username': user.name}), 201
    # , {'Location': url_for('get_user', id = user.id, _external = True)}


# Helper Methods
def createUser(login_session):
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        DBSession = sessionmaker(bind=engine)
        session = DBSession()
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except Exception:
        return None


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # If this request does not have `X-Requested-With` header,
    # this could be a CSRF if not request.headers.get('X-Requested-With'):
    #     abort(403)
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    print("I'm in gconnect")
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data.decode('utf-8')
    print("code: %s" % code)
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
    print(credentials)
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    reqWithAccesToken = h.request(url, 'GET')
    result = json.loads(h.request(url, 'GET')[1].decode('utf-8'))
    print(result)
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
        print("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps(
            'Current user is already connected.'), 200)
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

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    DoesUserExist = getUserID(data['email'])
    if not DoesUserExist:
        DoesUserExist = createUser(login_session)
    login_session['user_id'] = DoesUserExist

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += '''
                " style = "width: 300px; height: 300px;border-radius: 150px;
                -webkit-border-radius: 150px;-moz-border-radius: 150px;">
            '''
    flash("you are now logged in as %s" % login_session['username'])
    return output

# DISCONNECT - Revoke a current user's token and reset their login_session
@app.route("/gdisconnect")
def gdisconnect():
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    # Only disconnect a connected user
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(json.dumps('Current user not connected.'),
                                 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Execute HTTP GET request to revoke current token.
    # access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    reqWithAccesToken = h.request(url, 'GET')
    available = json.loads(h.request(url, 'GET')[1].decode('utf-8'))
    print(available)
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    result = h.request(url, 'GET')[0]
    if result['status'] == '200' or available.get('error'):
        # Reset the user's session.
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        # response = make_response(json.dumps('Successfully disconnected'),
        #  200)
        # response.headers['Content-Type'] = 'application/json'
        # return response
        flash("You have logged out successfully")
        return redirect(url_for('showCategories'))
    else:
        response = make_response(json.dumps(
            'Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


@auth.verify_password
def verify_password(username_or_token, password):
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    # Try to see if it's a token first
    user_id = User.verify_auth_token(username_or_token)
    if user_id:
        user = session.query(User).filter_by(id=user_id).one()
    else:
        user = session.query(User).filter_by(name=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True


@app.route('/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token()
    return jsonify({'token': token.decode('ascii')})


@app.route('/catalog/JSON')
def categoriesJSON():
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    category = session.query(Category).all()
    cats = []
    for cat in category:
        catItems = session.query(CategoryItem).filter_by(cat_id=cat.id).all()
        cat2 = cat.serialize
        cat2['item'] = [i.serialize for i in catItems]
        cats.append(cat2)
    return jsonify(Category=cats)


@app.route('/categories/<int:cat_id>/JSON')
def categoryMenuJSON(cat_id):
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    category = session.query(Category).filter_by(id=cat_id).one()
    items = session.query(CategoryItem).filter_by(
        cat_id=cat_id).all()
    return jsonify(CategoryItems=[i.serialize for i in items])


@app.route('/categories/<int:cat_id>/menu/<int:menu_item>/JSON')
def categoryCategoryItemJSON(cat_id, menu_item):
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    category = session.query(Category).filter_by(id=cat_id).one()
    item = session.query(CategoryItem).filter_by(
        cat_id=cat_id, id=menu_item).one()
    return jsonify(CategoryItems=item.serialize)


# Show all categories
@app.route('/')
@app.route('/categories/')
def showCategories():
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    categories = session.query(Category).order_by(asc(Category.name))
    return render_template('categories.html', categories=categories,
                           logged_in='username' in login_session)


# Create a new Category
@app.route('/category/new/', methods=['GET', 'POST'])
def newCategory():
    print(login_session)
    if 'username' not in login_session:
        return redirect('/login')
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    if request.method == 'POST':
        newCategory = Category(name=request.form['name'],
                               user_id=login_session['user_id'])
        session.add(newCategory)
        flash('New Category %s Successfully Created' % newCategory.name)
        session.commit()
        return redirect(url_for('categoryMenu', cat_id=newCategory.id))
    else:
        return render_template('newCategory.html')


# Edit a Category
@app.route('/category/<int:cat_id>/edit/', methods=['GET', 'POST'])
def editCategory(cat_id):
    if 'username' not in login_session:
        return redirect('/login')
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    editedCategory = session.query(
        Category).filter_by(id=cat_id).one()
    if login_session['user_id'] != editedCategory.user_id:
        return """
        <script>function myFunction(){ alert('UnAuthorized Action') }
        </script><body onload='myFunction()'>
        """
    if request.method == 'POST':
        if request.form['name']:
            editedCategory.name = request.form['name']
            flash('Category Successfully Edited %s' % editedCategory.name)
            session.commit()
            return redirect(url_for('categoryMenu', cat_id=cat_id))
    else:
        return render_template('editCategory.html', category=editedCategory)


# Delete a Category
@app.route('/category/<int:cat_id>/delete/', methods=['GET', 'POST'])
def deleteCategory(cat_id):
    if 'username' not in login_session:
        return redirect('/login')
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    categoryToDelete = session.query(
        Category).filter_by(id=cat_id).one()
    if login_session['user_id'] != categoryToDelete.user_id:
        return """
        <script>function myFunction(){ alert('UnAuthorized Action') }
        </script><body onload='myFunction()'>
        """
    if request.method == 'POST':
        categoryItems = session.query(CategoryItem).filter_by(
                        cat_id=cat_id).delete()
        session.delete(categoryToDelete)
        flash('%s Successfully Deleted' % categoryToDelete.name)
        session.commit()
        return redirect(url_for('showCategories'))
    else:
        return render_template('deleteCategory.html',
                               category=categoryToDelete)


@app.route('/categories/<int:cat_id>/')
def categoryMenu(cat_id):
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    output = ""
    output += "<html><body>"
    output += "<ol>"
    MyCat = session.query(Category).filter_by(id=cat_id).one()
    items = session.query(CategoryItem).filter_by(cat_id=cat_id)
    CanEdit = False
    if ('username' in login_session and
            login_session['user_id'] == MyCat.user_id):
        CanEdit = True
    Creator = session.query(User).filter_by(id=MyCat.user_id).one()
    return render_template('menu.html', category=MyCat, items=items,
                           CanEdit=CanEdit, Creator=Creator)


# Task 1: Create route for newCategoryItem function here
@app.route('/category/<int:cat_id>/new/', methods=['GET', 'POST'])
def newCategoryItem(cat_id):
    if 'username' not in login_session:
        return redirect('/login')
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    if request.method == 'POST':
        newItem = CategoryItem(name=request.form['name'],
                               description=request.form['description'],
                               cat_id=cat_id, user_id=login_session['user_id'])
        flash("New Category item created")
        session.add(newItem)
        session.commit()
        return redirect(url_for('categoryMenu', cat_id=cat_id))
    else:
        return render_template('newcategoryitem.html', cat_id=cat_id)


# Task 2: Create route for editCategoryItem function here
@app.route('/category/<int:cat_id>/<int:menu_id>/edit/',
           methods=['GET', 'POST'])
def editCategoryItem(cat_id, menu_id):
    if 'username' not in login_session:
        return redirect('/login')
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    editedItem = session.query(CategoryItem).filter_by(id=menu_id).one()
    if login_session['user_id'] != editedItem.user_id:
        return """
        <script>function myFunction(){ alert('UnAuthorized Action') }
        </script><body onload='myFunction()'>
        """
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        session.commit()
        flash("Edit menu item successful")
        return redirect(url_for('categoryMenu', cat_id=cat_id))
    else:
        # USE THE RENDER_TEMPLATE FUNCTION BELOW TO SEE THE VARIABLES YOU
        # SHOULD USE IN YOUR EDITCategoryItem TEMPLATE
        return render_template('editcategoryitem.html',
                               cat_id=cat_id, menu_id=menu_id,
                               item=editedItem)


# Task 3: Create a route for deleteCategoryItem function here
@app.route('/category/<int:cat_id>/<int:menu_id>/delete/',
           methods=['GET', 'POST'])
def deleteCategoryItem(cat_id, menu_id):
    if 'username' not in login_session:
        return redirect('/login')
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    deleteItem = session.query(CategoryItem).filter_by(id=menu_id).one()
    if login_session['user_id'] != deleteItem.user_id:
        return """
        <script>function myFunction(){ alert('UnAuthorized Action') }
        </script><body onload='myFunction()'>
        """
    if request.method == 'POST':
        session.delete(deleteItem)
        session.commit()
        flash("Menu item deleted")
        return redirect(url_for('categoryMenu', cat_id=cat_id))
    else:
        # USE THE RENDER_TEMPLATE FUNCTION BELOW TO SEE THE VARIABLES YOU
        # SHOULD USE IN YOUR EDITCategoryItem TEMPLATE
        return render_template(
            'deletecategoryitem.html', item=deleteItem)


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
