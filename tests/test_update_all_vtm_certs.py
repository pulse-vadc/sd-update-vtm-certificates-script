# Copyright 2019 Pulse Secure, LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json

import update_all_vtm_certificates
from unittest import TestCase
from unittest.mock import patch, call

SD_URL = 'sd-url'
CURRENT_CERT = "MIIDYDCCAkigAwIBAgIJAOJ0A/kfJH2NMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwHhcNMTkwNjA2MDkxMTUwWhcNMjkwNjAzMDkxMTUwWjBFMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2TS4C9N/ZiysNd7rgxDrrg+ayeKSHmrj+e6Mv8tpUwyzw0dKVZtgkM3Jwdyp2EI8QGA2kYgidcjcsNgCsfxxPkCxHktd3oZ/B+9yF2SzIxtoSIywd/4ZcN7uutg853UUYCNv7QF8t4tHaGNArPO8jBgvPnEu0QBC/wl3UrasPIgwZ5fWMs3cKJHmXCyjHpCQdD25k3OxVITeS+i5ru5FaI4U23Fy8vieU/saaR3Xe91/a1PdNI5amRYAQNeBygad3uiwBKA9ihsb85Y08PA3Bmx4f6M0l4OHtT6jzo8+lbwMZJW4IRcHUUlamaAZmV+jBFPqM2Zo35GZeq6tk9WuQQIDAQABo1MwUTAdBgNVHQ4EFgQU+C9S8Jarck9KvpdDbhrmrNxeS58wHwYDVR0jBBgwFoAU+C9S8Jarck9KvpdDbhrmrNxeS58wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEABE1b4W5/RJphEhtrZXqBvVxzRp/AFR8XzjOlD9tA2OtQ+LYRgTITSnKTdVlsXj737fumJzviS4QzLgKkdhnfhicAHCkHPnvatrPm8eRUspxPbfUY2zfDy9bz0T7fhUMLRFb3yjoC7aRB0C7n5x7ROgxDfgkxXaTqiQ/A2qk8XMeGTC2P1fd1PPhNX2NQhOOdqP3TbgtPX5TJ/c2EUIX+4G5whOSLbpG4I3bz2CIwaBabk/vfPUovUAmG1ciTBF53qcRgAAt0T+CQywp57QufPNSUDvIv2z6oYw5wPB20nD9fCXWP2OEVqMiOFlgUzidzKWzlSozY73b/qstzc3jdlg=="
NEW_CERT = "MIIDYDCCAkigAwIBAgIJAJogmQrb/pLnMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwHhcNMTkwNjA2MDkxMjAzWhcNMjkwNjAzMDkxMjAzWjBFMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvQfrsu/KAOIjKlI/UPk2paSRwkTjQonVCEYamQCbJJkCO9pazFqyE6zg0BXTI8ara46ci1noYyGWmiaXFnaEJNAuJ9nhkMpOiRgTF0anpD+3pEBlv1ZZ/i0d+7Q9QsTV46hwnQDka8bduWVy+mI1Lr2zDrnQknHcPxVO6MX1qlyghizwzW8VtyBflgoWqtnveETO3dvQPdjdtvSm805xP2JdvO4UqaxKVuaeTT/xmEfZ2tpoF0rkBCtU7w2ekNaSs7ZtVrCSD6kDHA4U3GsRIMcYsuKCM7KcACHEEb9M2tmiqMhDfh1Q5CiUvtbD0AmmcT51QI6u10zTKbLN9xnVRwIDAQABo1MwUTAdBgNVHQ4EFgQU1Btz6iTvoyH76gQ/1IFY2kyvgIYwHwYDVR0jBBgwFoAU1Btz6iTvoyH76gQ/1IFY2kyvgIYwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAg2Jn3eCdjf/r7eAa5K6KfVnIgnQ4MIa9vhY1Gihns1Kb7GxbTZlb4dXBoE74xMmqWj+OPLeHETJlD+a4uOQotpbro1+3Fa0ZNTQNIXGKg3JmxvbmQjzJZQ3A5o0M/ZYz8ZwsLRJKSF0yb+Ia1Fx6uSiVrpJ++BPCXOvCmjr37rwUvmgdif9msgaY8avDVzmNJGi94PXt3rDIZ2FygJHzsfidR/9anyHOdT7vcEthcxAtXlFgQFbM3rbuPdwxmbEjKIR4L9aBJJHOHjJ61JT3Eyh/pUih+eaF7d9nBxVApGXfsgT7iEQd3jTnkHXNjyoZtyI2XDn8OHp2MD/OgAXMCA=="


class MockResponse:
    """
    Mock response object, to be returned by MockSession in
    response to API queries
    """
    def __init__(self, status_code, json_resp=None):
        self.status_code = status_code
        self.json_resp = json_resp

    def json(self):
        return self.json_resp


class TestUpdateAllVtmCerts(TestCase):
    class UpdateAllCliParams:
        """
        Cli Parameters to be passed to the script
        """
        def __init__(self):
            self.remove_old_certificates = False
            self.new_sd_service_certificate = 'tests/new_cert.pem'
            self.current_sd_service_certificate = 'tests/current_cert.pem'
            self.sd_url = SD_URL
            self.sd_username = 'admin'
            self.sd_password = 'master1M@'
            self.new_private_key = 'tests/new_key.pem'
            self.vtms_to_update = False

    class MockSession:
        """
        Mock the SD rest API for testing
        """
        def __init__(self):
            self.Instance_R08P_server_certificate = CURRENT_CERT
            self.Instance_R08P_server_certificate_secondary = ""
            self.Instance_NL76_server_certificate = CURRENT_CERT
            self.Instance_NL76_server_certificate_secondary = ""

        def mount(self, *args, **kwargs):
            pass

        def put(self, url, *args, **kwargs):
            print('PUT: {0}'.format(url))

            if url == SD_URL + '/api/tmcm/2.8/manager/10.62.134.205':
                return MockResponse(200)

            if url == SD_URL + '/api/tmcm/2.8/instance/Instance-R08P-H4SF-M5AD-W1Y8/tm/6.2/config/active/global_settings?expert_keys=remote_licensing/server_certificate_secondary':
                assert kwargs['data']
                remote_licensing = json.loads(kwargs['data'])['properties']['remote_licensing']
                if 'server_certificate' in remote_licensing:
                    self.Instance_R08P_server_certificate = remote_licensing['server_certificate']
                if 'server_certificate_secondary' in remote_licensing:
                    self.Instance_R08P_server_certificate_secondary = remote_licensing['server_certificate_secondary']
                return MockResponse(200)

            if url == SD_URL + '/api/tmcm/2.8/instance/Instance-NL76-U3R2-LEF6-FOT9/tm/6.2/config/active/global_settings?expert_keys=remote_licensing/server_certificate_secondary':
                assert kwargs['data']
                remote_licensing = json.loads(kwargs['data'])['properties']['remote_licensing']
                if 'server_certificate' in remote_licensing:
                    self.Instance_NL76_server_certificate = remote_licensing['server_certificate']
                if 'server_certificate_secondary' in remote_licensing:
                    self.Instance_NL76_server_certificate_secondary = remote_licensing['server_certificate_secondary']
                return MockResponse(200)

            raise NotImplementedError('Unrecognised url')

        def get(self, url, *args, **kwargs):
            print('GET: {0}'.format(url))

            if url == SD_URL + '/api/common/1.1':
                return MockResponse(200)

            if url == SD_URL + '/api/common/1.1/info':
                return MockResponse(200, {'device_name': "10.62.134.205"})

            if url == SD_URL + '/api/tmcm/2.8/manager/10.62.134.205':
                return MockResponse(200, {"monitoring": "all"})

            if url == SD_URL + '/api/tmcm/2.8/instance':
                return MockResponse(200, {
                    "children": [
                        {
                            "name": "Instance-R08P-H4SF-M5AD-W1Y8"
                        },
                        {
                            "name": "Instance-NL76-U3R2-LEF6-FOT9"
                        },
                        {
                            "name": "Instance-FD98-S9V0-VDS9-NYN1"
                        },
                        {
                            "name": "Instance-KY25-Y9M1-YUK5-YJL5"
                        }
                    ]
                })

            if url == SD_URL + '/api/tmcm/2.8/instance/Instance-R08P-H4SF-M5AD-W1Y8':
                return MockResponse(200, {
                    "status": "Active",
                    "client_cert": "foo",
                })

            if url == SD_URL + '/api/tmcm/2.8/instance/Instance-NL76-U3R2-LEF6-FOT9':
                return MockResponse(200, {
                    "status": "Active",
                    "client_cert": "foo",
                })

            # Test a non-comms vTM
            if url == SD_URL + '/api/tmcm/2.8/instance/Instance-FD98-S9V0-VDS9-NYN1':
                return MockResponse(200, {
                    "status": "Active",
                    "client_cert": "",
                })

            # Test a deleted vTM
            if url == SD_URL + '/api/tmcm/2.8/instance/Instance-KY25-Y9M1-YUK5-YJL5':
                return MockResponse(200, {
                    "status": "Deleted",
                    "client_cert": "foo",
                })

            if url == SD_URL + '/api/tmcm/2.8/instance/Instance-R08P-H4SF-M5AD-W1Y8/tm/6.2/config/active/global_settings?expert_keys=remote_licensing/server_certificate_secondary':
                return MockResponse(200, {
                    "properties": {
                        "remote_licensing": {
                            "server_certificate": self.Instance_R08P_server_certificate,
                            "server_certificate_secondary": self.Instance_R08P_server_certificate_secondary
                        }
                    }
                })

            if url == SD_URL + '/api/tmcm/2.8/instance/Instance-NL76-U3R2-LEF6-FOT9/tm/6.2/config/active/global_settings?expert_keys=remote_licensing/server_certificate_secondary':
                return MockResponse(200, {
                    "properties": {
                        "remote_licensing": {
                            "server_certificate": self.Instance_NL76_server_certificate,
                            "server_certificate_secondary": self.Instance_NL76_server_certificate_secondary
                        }
                    }
                })

            if url == SD_URL + '/api/tmcm/2.8/instance/Instance-R08P-H4SF-M5AD-W1Y8/tm':
                return MockResponse(200)

            if url == SD_URL + '/api/tmcm/2.8/instance/Instance-NL76-U3R2-LEF6-FOT9/tm':
                return MockResponse(200)

            raise NotImplementedError('Unrecognised url')

    @patch('requests.Session', return_value=MockSession())
    @patch('update_all_vtm_certificates.get_args', return_value=UpdateAllCliParams())
    def test_update_and_clear(self, mock_cli_args, mock_session):
        # Check that the MockSession is in the correct initial configuration
        self.assertEqual(
            mock_session().Instance_NL76_server_certificate,
            CURRENT_CERT
        )
        self.assertEqual(
            mock_session().Instance_NL76_server_certificate_secondary,
            ""
        )
        self.assertEqual(
            mock_session().Instance_R08P_server_certificate,
            CURRENT_CERT
        )
        self.assertEqual(
            mock_session().Instance_R08P_server_certificate_secondary,
            ""
        )

        # Update the server certs
        update_all_vtm_certificates.main()

        self.assertEqual(
            mock_session().Instance_NL76_server_certificate,
            NEW_CERT
        )
        self.assertEqual(
            mock_session().Instance_NL76_server_certificate_secondary,
            CURRENT_CERT

        )
        self.assertEqual(
            mock_session().Instance_R08P_server_certificate,
            NEW_CERT
        )
        self.assertEqual(
            mock_session().Instance_R08P_server_certificate_secondary,
            CURRENT_CERT
        )

        # Now clear the server_certificate_secondary
        mock_cli_args().remove_old_certificates = True
        update_all_vtm_certificates.main()

        self.assertEqual(
            mock_session().Instance_NL76_server_certificate,
            NEW_CERT
        )
        self.assertEqual(
            mock_session().Instance_NL76_server_certificate_secondary,
            ""

        )
        self.assertEqual(
            mock_session().Instance_R08P_server_certificate,
            NEW_CERT
        )
        self.assertEqual(
            mock_session().Instance_R08P_server_certificate_secondary,
            ""
        )

        # Clear it again to check that the info responses are correct
        with patch('builtins.print') as mocked_print:
            update_all_vtm_certificates.main()
            self.assertIn(call('INFO - server_certificate_secondary has already been cleared from '
                               'vtm Instance-R08P-H4SF-M5AD-W1Y8'), mocked_print.mock_calls)
            self.assertIn(call('INFO - server_certificate_secondary has already been cleared from '
                               'vtm Instance-NL76-U3R2-LEF6-FOT9'), mocked_print.mock_calls)
