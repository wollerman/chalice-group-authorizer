from chalice.app import Chalice, error_response, ChaliceError
from chalice import CognitoUserPoolAuthorizer
import abc


class AbstractAuthorizer:
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def authorized(self, requester_group, requester_sub, requester_username, patient_id):
        return False


class CustomAdminAuthorizer(CognitoUserPoolAuthorizer, AbstractAuthorizer):
    def __init__(self, provider_arns, header='Authorization'):
        self.name = 'admin'
        super(CustomAdminAuthorizer, self).__init__(self.name, provider_arns, header)

    def authorized(self, requester_group, requester_sub, requester_username, patient_id):
        if self.name.lower() in requester_group:
            return True
        return False


class CustomPatientAuthorizer(CognitoUserPoolAuthorizer, AbstractAuthorizer):
    def __init__(self, provider_arns, header='Authorization'):
        self.name = 'patient'
        super(CustomPatientAuthorizer, self).__init__(self.name, provider_arns, header)

    def authorized(self, requester_group, requester_sub, requester_username, patient_id):
        if 'admin' in requester_group:
            return True
        elif self.name.lower() in requester_group:
            if requester_sub == patient_id:
                return True
        return False


class CustomCognitoUserAuthorizer(CognitoUserPoolAuthorizer, AbstractAuthorizer):
    def __init__(self, provider_arns, header='Authorization'):
        self.name = 'cognito_user'
        super(CustomCognitoUserAuthorizer, self).__init__(self.name, provider_arns, header)

    def authorized(self, requester_group, requester_sub, requester_username, patient_id):
        return True


class CustomAuthService(Chalice):
    def __init__(self, app_name="CustomAuthService", configure_logs=True):
        self.provider_arn = 'arn:aws:cognito-idp:us-west-2:299319460143:userpool/<<POOL_ID>>'
        self.patient_authorizer = CustomPatientAuthorizer(header='Authorization',
                                                          provider_arns=[self.provider_arn])

        self.admin_authorizer = CustomAdminAuthorizer(header='Authorization',
                                                      provider_arns=[self.provider_arn])

        self.cognito_user_authorizer = CustomCognitoUserAuthorizer(header='Authorization',
                                                                   provider_arns=[self.provider_arn])

        Chalice.__init__(self, app_name=app_name, configure_logs=configure_logs)

    def route(self, path, **kwargs):
        authorizer = kwargs.get('authorizer', None)
        if authorizer == 'public':
            kwargs['authorizer'] = None
        elif authorizer == 'cognito_user':
            kwargs['authorizer'] = self.cognito_user_authorizer
        elif authorizer == 'admin':
            kwargs['authorizer'] = self.admin_authorizer
        elif authorizer == 'patient':
            kwargs['authorizer'] = self.patient_authorizer
        else:
            # must explicitly determine authorizer
            raise EnvironmentError("Must explicitly provide an authorizer group on every route!")

        return super(CustomAuthService, self).route(path, **kwargs)

    def __call__(self, event, context):
        # immediately check permissions when lambda is called
        resource_path = event.get('requestContext', {}).get('resourcePath')
        if resource_path is None:
            return error_response(error_code='InternalServerError',
                                  message='Unknown request.',
                                  http_status_code=500)
        http_method = event['requestContext']['httpMethod']
        if resource_path not in self.routes:
            raise ChaliceError("No view function for: %s" % resource_path)
        if http_method not in self.routes[resource_path]:
            return error_response(
                error_code='MethodNotAllowedError',
                message='Unsupported method: %s' % http_method,
                http_status_code=405)
        route_entry = self.routes[resource_path][http_method]
        # self.log.debug(event['pathParameters'])
        # self.log.debug(event['requestContext'])
        # self.log.debug(event['stageVariables'])

        if route_entry.authorizer:
            request = event.get('requestContext', None)
            self.log.debug(request)
            if not request:
                return error_response(error_code='Unauthorized', message='Missing request context.',
                                      http_status_code=401)

            requester_claim = request.get('authorizer', {}).get('claims', None)
            if not requester_claim:
                return error_response(error_code='Unauthorized', message='Missing requester claim.',
                                      http_status_code=401)

            requester_sub = requester_claim.get('sub', None)
            if not requester_sub:
                return error_response(error_code='Unauthorized', message='Missing requester sub.',
                                      http_status_code=401)

            requester_username = requester_claim.get('cognito:username', '')
            self.log.debug("Request from cognito user '{}' with sub '{}'".format(requester_username, requester_sub))

            requester_group = requester_claim.get('cognito:groups', None)
            if not requester_group:
                return error_response(error_code='Unauthorized', message='Missing requester group.',
                                      http_status_code=401)

            self.log.debug("Checking auth for requester_group: {} and route auth name: {}".format(requester_group,
                                                                                                  route_entry.authorizer.name))
            requester_group = requester_group.split(',')

            try:
                patient_id = event['pathParameters']['patient_id']
            except KeyError:
                patient_id = None
            except TypeError:
                patient_id = None
            self.log.debug("checking against patient_id: '{}'".format(patient_id))
            self.log.debug("patient_id type: {}".format(type(patient_id)))
            self.log.debug("patient_id is coming from pathParams: {}".format(event['pathParameters']))
            self.log.debug(route_entry.authorizer.authorized(requester_group, requester_username, patient_id))
            if not route_entry.authorizer.authorized(requester_group, requester_sub, requester_username, patient_id):
                return error_response(error_code='Unauthorized', message='Incorrect permissions.', http_status_code=401)

        return super(CustomAuthService, self).__call__(event, context)
