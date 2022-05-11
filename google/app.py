from pip._vendor import cachecontrol
import google
import pathlib
from flask import Flask, redirect, render_template, session, abort, request
from google_auth_oauthlib.flow import Flow
from google.oauth2 import id_token
import os
import requests


app = Flask('Google Login App')
app. secret_key=os.urandom(24)

os.environ['OAUTHLIB_INSECURE_TRANSPORT']='1'


GOOGLE_CLIENT_ID="781263565771-gcnegtme1cv64pk9ljun838mirdac9kj.apps.googleusercontent.com"
client_secrets_file=os.path.join(pathlib.Path(__file__).resolve().parent, 'client_secret.json')


flow=Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes = ['https://www.googleapis.com/auth/userinfo.profile',
             'https://www.googleapis.com/auth/userinfo.email', 'openid'],
    redirect_uri = 'http://localhost:5000/callback'
    )


def login_is_required(function):
    def wrapper(*args, **kwargs):
        if 'google_id' not in session:
            return abort(401)
        else:
            return function()
    return wrapper


@app.route('/login')
def login():
    authorization_url, state = flow.authorization_url()
    session['state']=state
    return redirect(authorization_url)


@app.route('/callback')
def callback():
    flow.fetch_token(authorization_response=request.url)

    if not session['state'] == request.args['state']:
        abort(500) # state does not match!
    
    credentials = flow.credentials
    request_session = requests.session()
    cached_session=cachecontrol.CacheControl(request_session)
    token_request=google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials.id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )


    session['google_id']=id_info.get('sub')
    session['name'] = id_info.get('name')


    return redirect('/protected_area')


@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')


@app.route('/')
def index():
    return render_template('index.html') 
    


@app.route('/protected_area')
@login_is_required
def protected_area():
    return render_template('protected_area.html')



if __name__=='__main__':
    app.run(debug=True)


