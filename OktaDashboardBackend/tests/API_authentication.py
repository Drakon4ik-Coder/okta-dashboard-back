import unittest
from unittest.mock import patch
import requests


class OktaAuthenticationTestCase(unittest.TestCase):
    def setUp(self):
        # Defining the authentication details : client id, secret and private key for getting the access token
        self.client_id = "test_client_id"
        self.client_secret = "test_client_secret"
        self.key_id = "test_key_id"
        self.private_key = "-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgk...Your_Key...\n-----END PRIVATE KEY-----"
        self.token_url = "https://your-okta-domain.com/oauth2/v1/token"

    @patch('requests.post')
    def test_okta_authentication_success(self, mock_post):

        # Simulate a successful token response
        mock_response = {
            "access_token": "mock_access_token",
            "expires_in": 3600,
            "token_type": "Bearer"
        }

        # Mock the response from Okta API
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = mock_response

        # Perform the request
        response = requests.post(
            url=self.token_url,
            data={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret
            }
        )


        self.assertEqual(response.status_code, 200)
        self.assertIn("access_token", response.json())
        self.assertEqual(response.json()["access_token"], "mock_access_token")

    @patch('requests.post')  # Mock the 'requests.post' method
    def test_okta_authentication_failure(self, mock_post):

        # Simulate an error response from Okta
        mock_error_response = {
            "error": "invalid_client",
            "error_description": "Client authentication failed."
        }

        # Mock the response from Okta API
        mock_post.return_value.status_code = 401
        mock_post.return_value.json.return_value = mock_error_response

        # Perform the request
        response = requests.post(
            url=self.token_url,
            data={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": "wrong_client_secret"
            }
        )

        # Assertions
        self.assertEqual(response.status_code, 401)
        self.assertIn("error", response.json())
        self.assertEqual(response.json()["error"], "invalid_client")

if __name__ == '__main__':
    unittest.main()
