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

"""
Script to update the service_ssl_certificate and service_ssl_certificate_secondary
on all vTMs known by the specified Services Director in a large vTM estate.
"""
import argparse
import json
import sys
import textwrap
import time
from getpass import getpass
from datetime import datetime, timedelta
import OpenSSL
import requests
from requests.auth import HTTPBasicAuth
from tqdm import tqdm
from urllib3 import PoolManager, Retry

FAILED_UPDATE_FILENAME = 'vTM-update-failed.txt'


def main():
    """
    Entrypoint for the script
    """
    is_monitoring_disabled = False
    sd_api = None
    initial_monitoring_state = None

    try:
        cli_args = get_args()

        if cli_args.remove_old_certificates:
            sd_api = SdApi(cli_args.sd_url, cli_args.sd_username, cli_args.sd_password,
                           cli_args.new_sd_service_certificate)
        else:
            sd_api = SdApi(cli_args.sd_url, cli_args.sd_username, cli_args.sd_password,
                           cli_args.current_sd_service_certificate)

        initial_monitoring_state = sd_api.get_monitoring()
        sd_api.set_monitoring('none')
        is_monitoring_disabled = True
        print('INFO - Disabled monitoring on Services Director')

        if cli_args.remove_old_certificates:
            if cli_args.vtms_to_update:
                raise ValueError(
                    'please set either --vtms-to-update or --remove-old-certificates')
            remove_old_certificates(cli_args, sd_api)
        elif cli_args.vtms_to_update:
            update_list(cli_args, sd_api)
        else:
            update_all_vtms(cli_args, sd_api)

    except (ValueError, NameError, OpenSSL.crypto.Error, CertificateError,
            SdApi.SdApiError, requests.exceptions.RequestException) as ex:
        # If anything goes wrong try to reset the initial_monitoring_state
        print('FATAL - {0}'.format(str(ex)))
        sys.exit(1)

    finally:
        if is_monitoring_disabled and sd_api is not None:
            try:
                sd_api.set_monitoring(initial_monitoring_state)
                print('INFO - Reset monitoring back to {initial_monitoring_state} on '
                      'Services Director'.format(initial_monitoring_state=initial_monitoring_state))
            except Exception as ex:
                print('WARN - Could not reset monitoring back to {initial_monitoring_state} on '
                      'Services Director'.format(initial_monitoring_state=initial_monitoring_state))
                raise ex


def remove_old_certificates(cli_args, sd_api):
    """
    To be run after the Service SSL Cert on SD has been updated. This method
    will remove the current-sd-service-certificate (Now old) from the vTMs
    """
    vtms_to_update = sd_api.find_all_comms_channel_vtms()[0]

    # In vtm world SSL certs are strings without a header, footer or line breaks
    current_ssl_service_cert = sd_api.format_cert(load_file(
        cli_args.current_sd_service_certificate))
    new_ssl_service_cert = sd_api.format_cert(load_file(cli_args.new_sd_service_certificate))

    # If we're here then we have connected to the SdApi with the new service certificate
    # so we don't need to validate that the user has the key. SD is set up correctly
    failed_vtms = []
    updated_vtms = []

    for vtm in tqdm(vtms_to_update, desc='Update vTMs ', ascii=True):
        try:
            # First check that vtm has the certificates set correctly
            server_certificate, server_certificate_secondary = sd_api.get_vtm_certs(vtm)
            if server_certificate != new_ssl_service_cert:
                raise ValueError('vTM is not using the new SSL Service Certificate in its '
                                 'server_certificate section. The new SSL Service Certificate is '
                                 ':{new_ssl_service_cert} vTM server_certificate is '
                                 ':{server_certificate}'.format(
                                     new_ssl_service_cert=new_ssl_service_cert,
                                     server_certificate=server_certificate
                                 ))

            if server_certificate_secondary == "":
                print('INFO - server_certificate_secondary has already been '
                      'cleared from vtm {vtm_name}'.format(vtm_name=vtm))
                updated_vtms.append(vtm)
                continue

            if server_certificate_secondary != current_ssl_service_cert:
                raise ValueError('vTM is not using the current (now old) SSL Service Certificate '
                                 'in its server_certificate_secondary position. '
                                 'The current SSL Service Certificate is '
                                 ':{current_ssl_service_cert} vTM server_certificate_secondary is '
                                 ':{server_certificate_secondary}'.format(
                                     server_certificate_secondary=server_certificate_secondary,
                                     current_ssl_service_cert=current_ssl_service_cert
                                 ))
            # Replace the current_ssl_service_cert with empty string in the secondary position
            sd_api.push_certs_to_vtm(vtm, '', new_ssl_service_cert)
            updated_vtms.append(vtm)

        except Exception as ex: #pylint: disable=broad-except
            print('WARN - Failed to update vtm {vtm_name}: {failure_reason}'.format(
                vtm_name=vtm, failure_reason=str(ex)
            ))
            failed_vtms.append(vtm)

    print_remove_cert_summary(updated_vtms, failed_vtms, vtms_to_update)


def update_list(cli_args, sd_api):
    """
    Update a list of vTMs, saved in a file (cli_args.vtms_to_update)
    in JSON format
    """
    with open(cli_args.vtms_to_update) as fil:
        vtms_to_update = json.load(fil)

    current_ssl_service_cert = load_file(cli_args.current_sd_service_certificate)
    new_ssl_service_cert = load_file(cli_args.new_sd_service_certificate)
    new_ssl_service_private_key = load_file(cli_args.new_private_key)

    # current_ssl_service_cert is validated by SdApi. Only validate new cert
    check_cert_key_match(new_ssl_service_cert, new_ssl_service_private_key)

    updated_vtms, failed_vtms = update_vtms(vtms_to_update, current_ssl_service_cert,
                                            new_ssl_service_cert, sd_api)

    print_retry_summary(updated_vtms, failed_vtms, vtms_to_update)


def update_all_vtms(cli_args, sd_api):
    """
    Connect to SD and find then update all vTMs that need updating
    """
    vtms_to_update, non_comms_vtms = sd_api.find_all_comms_channel_vtms()

    current_ssl_service_cert = load_file(cli_args.current_sd_service_certificate)
    new_ssl_service_cert = load_file(cli_args.new_sd_service_certificate)
    new_ssl_service_private_key = load_file(cli_args.new_private_key)

    # current_ssl_service_cert is validated by SdApi
    check_cert_key_match(new_ssl_service_cert, new_ssl_service_private_key)

    updated_vtms, failed_vtms = update_vtms(vtms_to_update, current_ssl_service_cert,
                                            new_ssl_service_cert, sd_api)

    print_simple_summary(updated_vtms, failed_vtms, non_comms_vtms)


def load_file(cert_path):
    """Load a file"""
    with open(cert_path) as cer:
        cert = cer.read()
    return cert


def check_cert_key_match(cert, private_key):
    """
    Check that a certificate and key match. This ensures that the user actually has
    the key for the cert that they are using.
    """
    try:
        cert_obj = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
    except OpenSSL.crypto.Error:
        raise CertificateError('new Services Director service '
                               'certificate is not correct: %s' % cert)

    try:
        private_key_obj = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, private_key)
    except OpenSSL.crypto.Error:
        raise CertificateError('new Services Director service '
                               'private key is not correct: %s' % private_key)

    context = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_METHOD)
    context.use_privatekey(private_key_obj)
    context.use_certificate(cert_obj)
    try:
        context.check_privatekey()
        return True
    except OpenSSL.SSL.Error:
        raise CertificateError(
            'new sd service private key and new sd service certificate do not match: %s' % cert)


def get_args():
    """
    Handle all user interaction
    """
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description='Script to connect to Services Director and update the '
                    'service_ssl_certificate and service_ssl_certificate_secondary '
                    'for all vTMs that are managed by that instance of Services Director.\n\n'
                    'If run without the --remove-old-certificates flag then this '
                    'script will put the new-sd-service-certificate into the '
                    'service_ssl_certificate slot on all vTMs, and the '
                    'current-sd-service-certificate into the service_ssl_certificate_'
                    'secondary slot on all vTMs. If any vTMs fail to update '
                    'then their names are listed in {FAILED_UPDATE_FILENAME}, '
                    'and they can be retried with the --vtms-to-update command. '
                    'Once all vTMs have been updated you should update the Service '
                    'SSL Certificate in Services Director.\n\n'
                    'When you are satisfied that the vTMs are connected to Services '
                    'Director using the new Service SSL Certificate you may want to '
                    'remove the current-sd-service-certificate from the service_'
                    'ssl_certificate_secondary slot on the vTMs. Once the '
                    'current-sd-service-certificate has been removed from the '
                    'vTMs they will no longer be able to use it. This can be '
                    'done using the --remove-old-certificates.\n\n'
                    'The service_ssl_certificate_secondary paramater is an expert '
                    'key on the vTM. It is normally hidden from users. To view the '
                    'service_ssl_certificate_secondary you need to use the REST '
                    'API and enable that expert key as follows /api/tmcm/2.8/'
                    'instance/<INSTANCE_NAME>/tm/6.2/config/active/global_settings'
                    '?expert_keys=remote_licensing/server_certificate_'
                    'secondary'.format(FAILED_UPDATE_FILENAME=FAILED_UPDATE_FILENAME)
    )

    parser.add_argument('-n', '--new-sd-service-certificate', type=str, required=True,
                        help='Path to the new Services Director service .cert file. ')
    parser.add_argument('-c', '--current-sd-service-certificate', type=str, required=True,
                        help='Path to the current Services Director service .cert file. ')
    parser.add_argument('-l', '--sd-url', type=str, required=True,
                        help='Url to services director rest API. This is usually the Service '
                             'Endpoint Address with a port number. eg. https://10.62.168.198:8100 '
                             'The IP address of the active node can also be used. Do not use the '
                             'IP address of the passive node.')
    parser.add_argument('-u', '--sd-username', type=str, required=True,
                        help='Username for Services Director.')
    parser.add_argument('-p', '--sd-password', type=str, required=False,
                        help='Password for Services Director. If this is not set then the script '
                             'will immediately prompt the user for the password. ')
    parser.add_argument('-r', '--vtms-to-update', type=str, required=False,
                        help='Path to a file that contains the names of vTMs to update in '
                             'JSON format. You can pass in the vTM-update-failed.txt file that is '
                             'output by this script to retry the failed vTMs.')
    parser.add_argument('-k', '--new-private-key', type=str, required=True,
                        help='Path to SSL private key for new certificate. Used to check that the '
                             'new certificate is valid and that you have the private key which is'
                             'required to update the Services Director service SSL cert.')
    parser.add_argument('-d', '--remove-old-certificates', action='store_true',
                        help='Remove the current SSL Service Certificate from the vTMs after '
                             'Services Director '
                             'has been updated. This will set the secondary server certificate on '
                             'the vTM to none so the vTMs will be unable to connect to an '
                             'Services Director instance with the old SSL Service Certificate. '
                             'This is useful '
                             'if you are retiring a certificate. \nThis script will check that '
                             'each vTM has the new Services Director service certificate before '
                             'removing the '
                             'current Services Director service certificate.')

    args = parser.parse_args()

    # Get the password interactively if the user doesn't want it in their logs
    if not args.sd_password:
        args.sd_password = getpass()

    return args


def update_vtms(vtms_to_update, current_ssl_service_cert, new_ssl_service_cert, sd_api):
    """
    Update a list of vTMs
    """
    updated_vtms = []
    failed_vtms = []

    for vtm in tqdm(vtms_to_update, desc='Update vTMs ', ascii=True):
        try:
            sd_api.push_certs_to_vtm(vtm, current_ssl_service_cert, new_ssl_service_cert)
            updated_vtms.append(vtm)
        except Exception as ex: #pylint: disable=broad-except
            print('WARN - Failed to update vtm {vtm_name}: {failure_reason}'.format(
                vtm_name=vtm, failure_reason=str(ex)
            ))
            failed_vtms.append(vtm)

    return updated_vtms, failed_vtms


def print_remove_cert_summary(updated_vtms, failed_vtms, vtms_to_update):
    """
    Print a summary after removing the server_certificate_secondary(s)
    """
    if updated_vtms:
        print('\nThe following vTMs have had their server_certificate_secondary removed:')
        print('\n'.join(updated_vtms))

    if failed_vtms:
        print('\nThere were errors updating the following vTMs.')
        print('\n'.join(failed_vtms))

    print('\nSummary:')
    print('  vtms to update         : {0}'.format(len(vtms_to_update)))
    print('  successfully updated   : {0}'.format(len(updated_vtms)))
    print('  failed to update       : {0}'.format(len(failed_vtms)))


def print_retry_summary(updated_vtms, failed_vtms, vtms_to_update):
    """
    Print a summary after processing a list of vTMs to retry
    """
    if updated_vtms:
        print('\nThe following vTMs were successfully updated:')
        print('\n'.join(updated_vtms))

    if failed_vtms:
        with open(FAILED_UPDATE_FILENAME, 'w') as fil:
            json.dump(failed_vtms, fil)
        print('\nThere were errors updating the following vTMs.')
        print('\n'.join(failed_vtms))
        print('A list of vTMs which were not updated has been saved in {fail_update_file_name} '
              'to retry these vTMs re-run this script with the paramater --vtms-to-update '
              '{fail_update_file_name}'. format(fail_update_file_name=FAILED_UPDATE_FILENAME))

    print('\nSummary:')
    print('  vtms to update         : {0}'.format(len(vtms_to_update)))
    print('  successfully updated   : {0}'.format(len(updated_vtms)))
    print('  failed to update       : {0}'.format(len(failed_vtms)))


def print_simple_summary(updated_vtms, failed_vtms, ignored_vtms):
    """
    Print a summary after finding vTMs to update, then updating them
    """
    if ignored_vtms:
        print('\nThe following vTMs are not using the comms channel:')
        print('\n'.join(ignored_vtms))

    if updated_vtms:
        print('\nThe following vTMs were successfully updated:')
        print('\n'.join(updated_vtms))

    if failed_vtms:
        with open(FAILED_UPDATE_FILENAME, 'w') as fil:
            json.dump(failed_vtms, fil)
        print('\nThere were errors updating the following vTMs.')
        print('\n'.join(failed_vtms))
        print('A list of vTMs which were not updated has been saved in {fail_update_file_name} '
              'to retry these vTMs re-run this script with the paramater --vtms-to-update '
              '{fail_update_file_name}'. format(fail_update_file_name=FAILED_UPDATE_FILENAME))

    print('\nSummary:')
    print('  not using comms channel: {0}'.format(len(ignored_vtms)))
    print('  successfully updated   : {0}'.format(len(updated_vtms)))
    print('  failed to update       : {0}'.format(len(failed_vtms)))

    if failed_vtms:
        print('\n' + textwrap.fill(
            'Some vTMs have not had their server_certificate_secondary updated. Please '
            'ensure that the server certificate is updated for these vTMs, either by retrying '
            'this script, or manually updating the server_certificate for each vTM. Once the '
            'server_certificate is updated on all vTMs you can change the SSL Service '
            'Certificate in services director.', 79))
    else:
        print('\nAll vTM server_certificate updates were successful. '
              'Please update the Service SSL Cert on Services Director.\n')


class IgnoreHostnameAdapter(requests.adapters.HTTPAdapter):
    """
    Verify the SSL cert without requiring a hostname check. At Pulse we use the same cert
    for both instances in an HA pair. This means that the hostname in the cert cannot
    match the hostname of an individual Services Director
    """
    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        self._pool_connections = connections
        self._pool_maxsize = maxsize
        self._pool_block = block
        self.poolmanager = PoolManager(num_pools=connections,
                                       maxsize=maxsize,
                                       block=block,
                                       assert_hostname=False,
                                       **pool_kwargs)


class SdApi:
    """
    Wrapper class for the Services Director API. Handles all interaction with
    Services Director.
    """
    HEADERS = {'Content-Type': 'application/json'}
    VTM_SETTINGS_URL = '{url}/api/tmcm/2.8/instance/{vtm_name}/tm/6.2/config/active/' \
                       'global_settings?expert_keys=remote_licensing/server_certificate_secondary'

    class SdApiError(Exception):
        """Exception thrown by SdApi"""
        pass

    def __init__(self, url, username, password, sd_api_cert_file):
        self.url = url
        self.sd_api_cert_file = sd_api_cert_file
        self.basic_auth = HTTPBasicAuth(username, password)
        self.session = requests.Session()

        # Don't overload SD, backoff_factor makes it wait between retries.
        retry = Retry(total=5, connect=3, read=3, backoff_factor=0.2)

        # Use a custom HTTPAdapter that doesn't verify that hostnames match
        self.session.mount('https://', IgnoreHostnameAdapter(max_retries=retry))

        # Ping the API here to check that credentials work
        # info_response = requests.get(
        info_response = self.session.get(
            '{url}/api/common/1.1'.format(url=self.url),
            auth=self.basic_auth,
            verify=self.sd_api_cert_file
        )

        if info_response.status_code != 200:
            raise self.SdApiError(
                'Cannot connect to Services Director REST API: {error_info}'.format(
                    error_info=info_response.text)
            )

    @staticmethod
    def format_cert(cert):
        """
        The vTM requires the CERT as a string without the leading or trailing
        lines or newline
        """
        return cert.replace(
            '-----BEGIN CERTIFICATE-----', '').replace(
                '-----END CERTIFICATE-----', '').replace('\n', '')

    def _get_active_node_ip(self):
        """
        Get the IP address of the active services director node in the HA pair.
        If we are not using HA then return the IP address of the only node
        :return: string IP address of the active node
        """
        info_response = self.session.get(
            '{url}/api/common/1.1/info'.format(url=self.url),
            auth=self.basic_auth,
            verify=self.sd_api_cert_file
        )

        if info_response.status_code != 200:
            raise self.SdApiError('Cannot get active node: {error_info}'.format(
                error_info=info_response.text
            ))

        return info_response.json()['device_name']

    def get_monitoring(self):
        """
        Return the current services director monitoring state
        """
        active_node_ip = self._get_active_node_ip()
        url = '{sd_url}/api/tmcm/2.8/manager/{active_node_ip}'.format(
            sd_url=self.url,
            active_node_ip=active_node_ip,
        )
        response = self.session.get(
            url, auth=self.basic_auth, verify=self.sd_api_cert_file,)

        if response.status_code != 200:
            raise self.SdApiError('Cannot query monitoring: {error_info}'.format(
                error_info=response.text
            ))

        return response.json()['monitoring']

    def set_monitoring(self, new_value):
        """
        Update the current services director monitoring state
        """
        active_node_ip = self._get_active_node_ip()
        url = '{sd_url}/api/tmcm/2.8/manager/{active_node_ip}'.format(
            sd_url=self.url,
            active_node_ip=active_node_ip,
        )
        response = self.session.put(
            url,
            data=json.dumps({"monitoring": new_value}),
            auth=self.basic_auth,
            verify=self.sd_api_cert_file,
            headers=self.HEADERS,
        )
        if response.status_code != 200:
            raise self.SdApiError(
                'Cannot set monitoring to {new_value} error is: {error_info}'.format(
                    error_info=response.text, new_value=new_value)
            )

    def find_all_comms_channel_vtms(self):
        """
        Find the vTMs that use the comms channel
        """
        comms_channel_vtms = []
        non_comms_channel_vtms = []

        all_vtms = self.session.get(
            '{url}/api/tmcm/2.8/instance'.format(url=self.url),
            auth=self.basic_auth,
            verify=self.sd_api_cert_file
        ).json()['children']

        for vtm in tqdm(all_vtms, desc='Query vTMs  ', ascii=True):
            vtm_details = self.session.get(
                '{url}/api/tmcm/2.8/instance/{vtm_name}'.format(
                    url=self.url, vtm_name=vtm['name']),
                auth=self.basic_auth,
                verify=self.sd_api_cert_file
            ).json()

            # Ignore any deleted vTMs
            if vtm_details['status'] == 'Deleted':
                continue

            if vtm_details['client_cert'] == "":
                non_comms_channel_vtms.append(vtm)
            else:
                comms_channel_vtms.append(vtm)

        # Return just the array of names
        return [d['name'] for d in comms_channel_vtms], [d['name'] for d in non_comms_channel_vtms]

    def _is_connection_to_vtm_open(self, vtm_name):
        url = '{url}/api/tmcm/2.8/instance/{vtm_name}/tm'.format(
            url=self.url, vtm_name=vtm_name)

        info_response = self.session.get(
            url, auth=self.basic_auth, verify=self.sd_api_cert_file
        )

        return info_response.status_code == 200

    def get_vtm_certs(self, vtm_name):
        """
        Get the server_certificate and server_certificate_secondary from a vTM
        """
        url = self.VTM_SETTINGS_URL.format(
            url=self.url, vtm_name=vtm_name
        )

        resp = self.session.get(
            url,
            auth=self.basic_auth,
            verify=self.sd_api_cert_file,
            headers=self.HEADERS,
        )

        rl_info = resp.json()['properties']['remote_licensing']
        return rl_info['server_certificate'], rl_info['server_certificate_secondary']

    def push_certs_to_vtm(self, vtm_name, server_certificate_secondary, server_certificate):
        """
        Update the server_certificate and server_certificate_secondary on a vTM
        """
        # The VTM requires the CERT as a string without the leading or trailing lines or newline
        server_certificate_st = self.format_cert(server_certificate)
        server_certificate_secondary_st = self.format_cert(server_certificate_secondary)

        url = self.VTM_SETTINGS_URL.format(
            url=self.url, vtm_name=vtm_name
        )

        data = {
            "properties": {
                "remote_licensing": {
                }
            }
        }

        # Work out which certs need updating. Don't change cert unless we need to.
        # vTM does not error if there is nothing in the put body
        remote_server_certificate, remote_server_cert_secondary = \
            self.get_vtm_certs(vtm_name)

        if remote_server_certificate != server_certificate_st:
            data['properties']['remote_licensing']['server_certificate'] = server_certificate_st

        if remote_server_cert_secondary != server_certificate_secondary_st:
            data['properties']['remote_licensing']['server_certificate_secondary'] = \
                server_certificate_secondary_st

        # Fire and forget. The vTM will create a new chanel and this one will close.
        # We won't see the response
        try:
            self.session.put(
                url,
                data=json.dumps(data),
                auth=self.basic_auth,
                verify=self.sd_api_cert_file,
                headers=self.HEADERS,
                timeout=(3.05, 0.5)
            )
        except requests.exceptions.Timeout:
            pass

        # Wait for vTM connection to re-establish
        retry_time_limit = datetime.now() + timedelta(seconds=20)
        while not self._is_connection_to_vtm_open(vtm_name) and datetime.now() < retry_time_limit:
            time.sleep(0.1)

        # Get the SSL certs to check that the operation happened successfully
        settings_response = self.session.get(
            url, auth=self.basic_auth, verify=self.sd_api_cert_file
        )

        vtm_remote_licensing = settings_response.json()['properties']['remote_licensing']

        if not (server_certificate_st == vtm_remote_licensing['server_certificate'] or
                server_certificate_secondary_st ==
                vtm_remote_licensing['server_certificate_secondary']):
            raise self.SdApiError('Failed to update vTM {vtm_name}'.format(vtm_name=vtm_name))


class CertificateError(Exception):
    """Error to do with validation of certificates"""
    pass


if __name__ == '__main__':
    main()
