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


"""
test_ms_ext_config
----------------------------------

Tests for `ms_ext_config` module.
"""

import etcd
import mock
import os

from ms_ext_config import start_script
from ms_ext_config.tests import base


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


class TestFillVariables(base.TestCase):

    def setUp(self):
        super(TestFillVariables, self).setUp()
        os.environ['CCP_VAR_FOO'] = 'CCP_VAL_FOO'

    def tearDown(self):
        super(TestFillVariables, self).tearDown()
        del os.environ['CCP_VAR_FOO']

    @mock.patch('__builtin__.open', mock.mock_open())
    @mock.patch('yaml.load')
    @mock.patch('ms_ext_config.start_script.create_network_topology')
    def test_fill_variables(self, m_create_network_topology, m_yaml_load):
        def side_effect(file_name):
            return {'glob': 'glob_val'}
        m_yaml_load.side_effect = side_effect
        m_create_network_topology.return_value = 'network_topology'
        r_value = start_script.fill_variables('role')
        e_value = {
            'glob': 'glob_val',
            'role_name': 'role',
            'network_topology': 'network_topology',
            'CCP_VAR_FOO': 'CCP_VAL_FOO'
        }
        self.assertEqual(r_value, e_value)


class TestRetry(base.TestCase):
    def setUp(self):
        super(TestRetry, self).setUp()
        start_script.VARIABLES = {
            'etcd_connection_attempts': 3,
            'etcd_connection_delay': 0
        }

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
