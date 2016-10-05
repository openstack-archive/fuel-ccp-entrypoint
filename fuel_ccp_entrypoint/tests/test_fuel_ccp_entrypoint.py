# -*- coding: utf-8 -*-

# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import os

import etcd
import mock

from fuel_ccp_entrypoint import start_script
from fuel_ccp_entrypoint.tests import base


class TestGetIpAddress(base.TestCase):

    def setUp(self):
        super(TestGetIpAddress, self).setUp()
        self.private_iface = 'eth0'
        self.public_iface = 'eth1'

    @mock.patch('netifaces.interfaces')
    @mock.patch('netifaces.ifaddresses')
    def test_get_ip_address_iface_wrong(self, m_ifaddresses, m_interfaces):
        m_interfaces.return_value = ['eth10', 'eth99']
        r_value = start_script.get_ip_address(self.private_iface)
        self.assertEqual('127.0.0.1', r_value)
        self.assertEqual(1, len(m_interfaces.mock_calls))
        self.assertEqual(0, len(m_ifaddresses.mock_calls))

    @mock.patch('netifaces.interfaces')
    @mock.patch('netifaces.ifaddresses')
    def test_get_ip_address_address_family_wrong(self, m_ifaddresses,
                                                 m_interfaces):
        m_interfaces.return_value = ['eth0', 'eth99']
        m_ifaddresses.return_value = {3: [{"addr": "8.8.8.8"}]}
        r_value = start_script.get_ip_address(self.private_iface)
        self.assertEqual('127.0.0.1', r_value)
        self.assertEqual(1, len(m_interfaces.mock_calls))
        self.assertEqual(1, len(m_ifaddresses.mock_calls))

    @mock.patch('netifaces.interfaces')
    @mock.patch('netifaces.ifaddresses')
    def test_get_ip_address_address_wrong(self, m_ifaddresses, m_interfaces):
        m_interfaces.return_value = ['eth0', 'eth99']
        m_ifaddresses.return_value = {2: [{"notaddr": "8.8.8.8"}]}
        r_value = start_script.get_ip_address(self.private_iface)
        self.assertEqual('127.0.0.1', r_value)
        self.assertEqual(1, len(m_interfaces.mock_calls))
        self.assertEqual(2, len(m_ifaddresses.mock_calls))

    @mock.patch('netifaces.interfaces')
    @mock.patch('netifaces.ifaddresses')
    def test_get_ip_address_address_good(self, m_ifaddresses, m_interfaces):
        m_interfaces.return_value = ['eth0', 'eth99']
        m_ifaddresses.return_value = {2: [{"addr": "8.8.8.8"}]}
        r_value = start_script.get_ip_address(self.private_iface)
        self.assertEqual('8.8.8.8', r_value)
        self.assertEqual(1, len(m_interfaces.mock_calls))
        self.assertEqual(2, len(m_ifaddresses.mock_calls))


class TestGetVariables(base.TestCase):

    def setUp(self):
        super(TestGetVariables, self).setUp()
        os.environ['CCP_VAR_FOO'] = 'CCP_VAL_FOO'
        os.environ['CCP_NODE_NAME'] = 'node1'

    def tearDown(self):
        super(TestGetVariables, self).tearDown()
        del os.environ['CCP_VAR_FOO']
        del os.environ['CCP_NODE_NAME']

    @mock.patch('six.moves.builtins.open', mock.mock_open())
    @mock.patch('json.load')
    @mock.patch('fuel_ccp_entrypoint.start_script.create_network_topology')
    def test_get_variables(self, m_create_network_topology, m_json_load):
        def side_effect(file_name):
            return {'glob': 'glob_val'}
        m_json_load.return_value = {'glob': 'glob_val'}
        m_create_network_topology.return_value = 'network_topology'
        r_value = start_script.get_variables('role')
        e_value = {
            'glob': 'glob_val',
            'role_name': 'role',
            'network_topology': 'network_topology',
            'node_name': 'node1',
            'CCP_VAR_FOO': 'CCP_VAL_FOO',
            'CCP_NODE_NAME': 'node1'
        }
        self.assertEqual(r_value, e_value)


class TestRetry(base.TestCase):
    def setUp(self):
        super(TestRetry, self).setUp()
        start_script.VARIABLES = {'etcd': {
            'connection_attempts': 3,
            'connection_delay': 0
        }}

    @start_script.retry
    def func_test(self):
        return self.func_ret()

    def test_retry_succeeded(self):
        self.func_ret = mock.Mock(side_effect=[
            etcd.EtcdException('test_error'), 'test_result'])
        self.assertEqual('test_result', self.func_test())
        self.assertEqual(2, self.func_ret.call_count)

    def test_retry_failed(self):
        self.func_ret = mock.Mock(side_effect=[
            etcd.EtcdException('test_error') for _ in range(3)])

        self.assertRaisesRegexp(
            etcd.EtcdException, 'test_error', self.func_test)
        self.assertEqual(3, self.func_ret.call_count)


class TestGetETCDClient(base.TestCase):
    def test_get_etcd_local_client(self):
        start_script.VARIABLES = {
            "role_name": "etcd",
            "etcd": {"client_port": 10042},
            "network_topology": {
                "private": {
                    "address": "192.0.2.1"
                }
            }
        }
        with mock.patch("etcd.Client") as m_etcd:
            expected_value = object()
            m_etcd.return_value = expected_value
            etcd_client = start_script.get_etcd_client()
            self.assertIs(expected_value, etcd_client)
            m_etcd.assert_called_once_with(
                host=(("192.0.2.1", 10042),),
                allow_reconnect=True,
                read_timeout=2)

    def test_get_etcd_client(self):
        start_script.VARIABLES = {
            "role_name": "banana",
            "namespace": "ccp",
            "etcd": {"client_port": 1234},
        }
        with mock.patch("etcd.Client") as m_etcd:
            expected_value = object()
            m_etcd.return_value = expected_value
            etcd_client = start_script.get_etcd_client()
            self.assertIs(expected_value, etcd_client)
            m_etcd.assert_called_once_with(
                host=(('etcd.ccp', 1234),),
                allow_reconnect=True,
                read_timeout=2)

    def test_get_etcd_client_wrong(self):
        start_script.VARIABLES = {
            "role_nmae": "banana"
        }
        self.assertRaises(KeyError, start_script.get_etcd_client)
