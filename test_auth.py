import unittest
from chalicelib import custom_auth_service


class TestAuthAsAdmin(unittest.TestCase):
    def setUp(self):
        self.requester_group = 'admin'
        self.username = '1234-5678-1234-5678'
        self.requester_sub = '8888-8888'
        self.requested_patient_id = '4444-4444'

    def test_patient(self):
        route_authorizer = custom_auth_service.CustomPatientAuthorizer([])
        res = route_authorizer.authorized(self.requester_group, self.requester_sub, self.username, self.requested_patient_id)
        self.assertTrue(res)

    def test_admin(self):
        route_authorizer = custom_auth_service.CustomAdminAuthorizer([])
        res = route_authorizer.authorized(self.requester_group, self.requester_sub, self.username, self.requested_patient_id)
        self.assertTrue(res)

    def test_admin_without_patientid(self):
        route_authorizer = custom_auth_service.CustomAdminAuthorizer([])
        res = route_authorizer.authorized(self.requester_group, self.requester_sub, self.username, None)
        self.assertTrue(res)

    def test_cognito_user(self):
        route_authorizer = custom_auth_service.CustomCognitoUserAuthorizer([])
        res = route_authorizer.authorized(self.requester_group, self.requester_sub, self.username, self.requested_patient_id)
        self.assertTrue(res)

    def test_cognito_user_without_patientid(self):
        route_authorizer = custom_auth_service.CustomCognitoUserAuthorizer([])
        res = route_authorizer.authorized(self.requester_group, self.requester_sub, self.username, None)
        self.assertTrue(res)


class TestAuthAsPatient(unittest.TestCase):
    def setUp(self):
        self.requester_group = 'patient'
        self.username = '0987-0987-0987-0987'
        self.requester_sub = '8888-8888'
        self.requested_patient_id = '4444-4444'

    def test_patient_self(self):
        route_authorizer = custom_auth_service.CustomPatientAuthorizer([])
        res = route_authorizer.authorized(self.requester_group, self.requester_sub, self.username, self.requester_sub)
        self.assertTrue(res)

    def test_patient_other(self):
        route_authorizer = custom_auth_service.CustomPatientAuthorizer([])
        res = route_authorizer.authorized(self.requester_group, self.requester_sub, self.username, self.requested_patient_id)
        self.assertFalse(res)

    def test_patient_without_patientid(self):
        route_authorizer = custom_auth_service.CustomPatientAuthorizer([])
        res = route_authorizer.authorized(self.requester_group, self.requester_sub, self.username, None)
        self.assertFalse(res)

    def test_admin(self):
        route_authorizer = custom_auth_service.CustomAdminAuthorizer([])
        res = route_authorizer.authorized(self.requester_group, self.requester_sub, self.username, self.requested_patient_id)
        self.assertFalse(res)

    def test_admin_without_patientid(self):
        route_authorizer = custom_auth_service.CustomAdminAuthorizer([])
        res = route_authorizer.authorized(self.requester_group, self.requester_sub, self.username, None)
        self.assertFalse(res)

    def test_cognito_user(self):
        route_authorizer = custom_auth_service.CustomCognitoUserAuthorizer([])
        res = route_authorizer.authorized(self.requester_group, self.requester_sub, self.username, self.requested_patient_id)
        self.assertTrue(res)

    def test_cognito_user_without_patientid(self):
        route_authorizer = custom_auth_service.CustomCognitoUserAuthorizer([])
        res = route_authorizer.authorized(self.requester_group, self.requester_sub, self.username, None)
        self.assertTrue(res)
