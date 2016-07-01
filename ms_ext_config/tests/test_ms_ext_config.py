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

import mock
from ms_ext_config import start_script
from ms_ext_config.tests import base


class TestMs_ext_config(base.TestCase):

    def setUp(self):
        super(TestMs_ext_config, self).setUp()
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
