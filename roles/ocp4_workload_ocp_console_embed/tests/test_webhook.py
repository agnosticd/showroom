import unittest
import json
import base64
from unittest.mock import patch, MagicMock
import sys
import os

# Add the files directory to sys.path so we can import the webhook script
sys.path.append(os.path.join(os.path.dirname(__file__), '../files'))

# Import the webhook module
import webhook

class TestWebhook(unittest.TestCase):

    def setUp(self):
        # Create a raw instance without calling __init__ to avoid socket/server setup
        self.handler = webhook.Handler.__new__(webhook.Handler)
        # Mock the allow method to return a simple dict for verification
        self.handler.allow = MagicMock(side_effect=lambda uid: {'response': {'uid': uid, 'allowed': True}})

    def test_handle_review_wrong_route(self):
        body = {
            'request': {
                'uid': '123',
                'object': {
                    'metadata': {'name': 'other-route', 'namespace': 'openshift-authentication'},
                    'spec': {'tls': {'termination': 'passthrough'}}
                }
            }
        }
        webhook.SERVICE_CA = "fake-ca"
        self.handler.handle_review(body, '123')
        self.handler.allow.assert_called_with('123')

    def test_handle_review_wrong_namespace(self):
        body = {
            'request': {
                'uid': '123',
                'object': {
                    'metadata': {'name': 'oauth-openshift', 'namespace': 'other-namespace'},
                    'spec': {'tls': {'termination': 'passthrough'}}
                }
            }
        }
        webhook.SERVICE_CA = "fake-ca"
        self.handler.handle_review(body, '123')
        self.handler.allow.assert_called_with('123')

    def test_handle_review_not_passthrough(self):
        body = {
            'request': {
                'uid': '123',
                'object': {
                    'metadata': {'name': 'oauth-openshift', 'namespace': 'openshift-authentication'},
                    'spec': {'tls': {'termination': 'reencrypt'}}
                }
            }
        }
        webhook.SERVICE_CA = "fake-ca"
        self.handler.handle_review(body, '123')
        self.handler.allow.assert_called_with('123')

    def test_handle_review_no_service_ca(self):
        body = {
            'request': {
                'uid': '123',
                'object': {
                    'metadata': {'name': 'oauth-openshift', 'namespace': 'openshift-authentication'},
                    'spec': {'tls': {'termination': 'passthrough'}}
                }
            }
        }
        webhook.SERVICE_CA = None
        self.handler.handle_review(body, '123')
        self.handler.allow.assert_called_with('123')

    def test_handle_review_success(self):
        body = {
            'request': {
                'uid': '123',
                'object': {
                    'metadata': {'name': 'oauth-openshift', 'namespace': 'openshift-authentication'},
                    'spec': {'tls': {'termination': 'passthrough'}}
                }
            }
        }
        webhook.SERVICE_CA = "fake-ca-content"
        
        # We need to verify the return value directly since it's not calling allow() in success case
        resp = self.handler.handle_review(body, '123')
        
        self.assertEqual(resp['kind'], 'AdmissionReview')
        self.assertTrue(resp['response']['allowed'])
        self.assertEqual(resp['response']['patchType'], 'JSONPatch')
        
        # Decode the patch
        patch_json = base64.b64decode(resp['response']['patch']).decode()
        patches = json.loads(patch_json)
        
        self.assertEqual(len(patches), 3)
        self.assertEqual(patches[0]['value'], 'reencrypt')
        self.assertEqual(patches[2]['value'], 'fake-ca-content')

if __name__ == '__main__':
    unittest.main()
