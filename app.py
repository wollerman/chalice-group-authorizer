from chalicelib import custom_auth_service

app = custom_auth_service.CustomAuthService(app_name='custom-auth-service')
app.debug = True


@app.route('/patient/{patient_id}', authorizer='patient')
def patients(patient_id):
    return {'hello': 'patient {}'.format(patient_id)}


@app.route('/admin', authorizer='admin')
def admin():
    return {'hello': 'admin'}


@app.route('/public', authorizer='public')
def public():
    return {'hello': 'public'}


@app.route('/cognito_user', authorizer='cognito_user')
def cognito_user():
    return {'hello': 'cognito_user'}
