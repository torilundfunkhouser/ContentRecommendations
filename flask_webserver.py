#!/usr/bin/env python
import sys
import httplib2
import json
import requests
import random
import string

from oauth2client.client import flow_from_clientsecrets, FlowExchangeError

from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker

from database_setup import Base, Content, Recommendations, User

from flask import session as login_session

from flask import Flask, render_template, request, redirect, jsonify, url_for, flash, make_response

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "content-recommendations"


# Connect to Database and create database session
engine = create_engine('sqlite:///recommendations1.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token

    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?'
    'grant_type=fb_exchange_token&client_id=%s&'
    'client_secret=%s&fb_exchange_token=%s%(app_id, app_secret, access_token)'
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = ('https://graph.facebook.com/v2.8/me?'
           'access_token=%s&fields=name,id,email%token')
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url = ('https://graph.facebook.com/v2.8/me/picture?'
           'access_token=%s&redirect=0&height=200&width=200%token')
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: '
    ' 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = ('https://graph.facebook.com/%s/permissions?'
    'access_token=%s%(facebook_id, access_token')
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    request.get_data()
    code = request.data.decode('utf-8')

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
    # Submit request, parse response - Python3 compatible
    h = httplib2.Http()
    response = h.request(url, 'GET')[1]
    str_response = response.decode('utf-8')
    result = json.loads(str_response)

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
        response = make_response(json.dumps('User is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't, make a new user
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius:" '
    ' " 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output

    # DISCONNECT - Revoke a current user's token and reset their login_session


# User Helper Functions

def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


# DISCONNECT - Revoke a current user's token and reset their login_session

@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        print 'Access Token is None'
        response = make_response(json.dumps('User not connected.'),
                                 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    print 'In gdisconnect access token is %s', access_token
    print 'User name is: '
    print login_session['username']
    url = ('https://accounts.google.com/o/oauth2'
           '/revoke?token=%s') % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print 'result is '
    print result
    if result['status'] == '200':
        # Reset the user's sesson.
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps('Failed to revoke token for user.',
                                 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# JSON APIs to view Content Information
@app.route('/content/<int:content_id>/rec/JSON')
def contentRecJSON(content_id):
    content = session.query(Content).filter_by(id=content_id).one()
    items = session.query(Recommendations).filter_by(
        content_id=content_id).all()
    return jsonify(RecItems=[i.serialize for i in items])


@app.route('/content/<int:content_id>/rec/<int:rec_id>/JSON')
def recItemJSON(content_id, rec_id):
    recItem = session.query(Recommendations).filter_by(id=rec_id).one()
    return jsonify(recItem=recItem.serialize)


@app.route('/content/JSON')
def contentJSON():
    content = session.query(Content).all()
    return jsonify(content=[r.serialize for r in content])


# Show all content
@app.route('/')
@app.route('/content/')
def showContent():
    content = session.query(Content).order_by(asc(Content.name))
    if 'username' not in login_session:
        return render_template('public_content.html', content=content)
    else:
        return render_template('content.html', content=content)

# Create a new recommendation

@app.route('/content/new/', methods=['GET', 'POST'])
def newContent():
    if 'username' not in login_session:
        return redirect('/login')
    content = session.query(Content).all()
    if request.method == 'POST':
        newContent = Content(
            name=request.form['name'],) #user_id=login_session['user_id'])
        session.add(newContent)
        session.commit()
        return redirect(url_for('showContent'))
    else:
        return render_template('new_content.html', content=content)


# Edit a content source

@app.route('/content/<int:content_id>/edit', methods=['GET', 'POST'])
def editContent(content_id):
    editedContent = session.query(Content).filter_by(id=content_id).one()
    item = editedContent
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        if request.form['name']:
            editedContent.name = request.form['name']
            return redirect(url_for('showContent'))
    else:
        return render_template('edit_content.html',
                               content_id=content_id,
                               content=editedContent)

# Delete a content source

@app.route('/content/<int:content_id>/delete', methods=['GET', 'POST'])
def deleteContent(content_id):
    if 'username' not in login_session:
        return redirect('/login')
    contentToDelete = session.query(
        Content).filter_by(id=content_id).one()
    content = session.query(Content).all()
    if request.method == 'POST':
        session.delete(contentToDelete)
        session.commit()
        return redirect(url_for('showContent', content_id=content_id))
    else:
        return render_template('delete_content.html',
                               content_id=content_id,
                               item=contentToDelete,
                               content=content)

# Show a content source's recommendations

@app.route('/content/<int:content_id>/')
@app.route('/content/<int:content_id>/recommendation/')
def showRecommendation(content_id):
    content = session.query(Content).filter_by(id=content_id).one()
    items = session.query(Recommendations).filter_by(content_id=content.id).all()
    if 'username' not in login_session:
        return render_template('public_recs.html',
                               items=items,
                               content=content)
    else:
        return render_template('recs.html', items=items, content=content)


# Create a new recommendation

@app.route('/content/<int:content_id>/recommendation/new/',
           methods=['GET', 'POST'])
def newRecommendations(content_id):
    if 'username' not in login_session:
        return redirect('/login')
    content = session.query(Content).filter_by(id=content_id).one()
    if request.method == 'POST':
        newItem = Recommendations(name=request.form['name'],
                                  description=request.form['description'],
                                  content_id=content_id,
                                  user_id=content.user_id)
        session.add(newItem)
        session.commit()
        return redirect(url_for('showRecommendation', content_id=content.id))
    else:
        return render_template('new_rec.html', content_id=content.id)


# Edit a Recommendation

@app.route('/content/<int:content_id>/<int:rec_id>/edit',
           methods=['GET', 'POST'])
def editRecommendations(content_id, rec_id):
    if 'username' not in login_session:
        return redirect('/login')
    editedItem = session.query(Recommendations).filter_by(id=rec_id).one()
    content = session.query(Content).filter_by(id=content_id).one()
    item = editedItem
    if request.method == 'POST':
        session.add(item)
        session.commit()
        return redirect(url_for('showRecommendation',
                                content_id=content_id,
                                rec_id=rec_id,
                                item=item))
    else:
        return render_template(
            'edit_rec.html', content_id=content_id, rec_id=rec_id, item=item)


# Delete a recommendation

@app.route('/content/<int:content_id>/<int:rec_id>/delete',
           methods=['GET', 'POST'])
def deleteRecommendations(content_id, rec_id):
    if 'username' not in login_session:
        return redirect('/login')
    recToDelete = session.query(Recommendations).filter_by(id=rec_id).one()
    content = session.query(Content).filter_by(id=content_id).one()
    if request.method == 'POST':
        session.delete(recToDelete)
        session.commit()
        return redirect(url_for('showRecommendation', content_id=content_id))
    else:
        return render_template(
            'delete_rec.html', content_id=content_id, rec_id=rec_id, item=recToDelete)


# Disconnect based on provider

@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['access_token']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('showContent'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showContent'))


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
