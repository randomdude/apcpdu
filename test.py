#!/usr/bin/python

#
# These are tests for the PDU interfacing code. They require the serial port of a connected PDU,
# and login creds. The tests will reconfigure the PDU and leave it in a different state!
#

import unittest2
import Infra_apcpdu

class Tests(unittest2.TestCase):
	@classmethod
	def setUpClass(self):
		self.username = 'apc'
		self.password = 'apc'
		self.port = '/dev/ttyUSB0'

	def createUUT(self):
		return Infra_apcpdu.Infra_apcpdu(self.port, self.username, self.password, False)

	def testSettingIP(self):
		for ip in ['1.1.1.1', '2.2.2.2']:
			with self.createUUT() as pdu:
				pdu.setTCPParams(IP=ip)
				self.assertEquals(ip, pdu.IP)

			with self.createUUT() as pdu:
				self.assertEquals(ip, pdu.IP)

	def testSettingTimezone(self):
		for tz in ['-01:00', '+10:00']:
			with self.createUUT() as pdu:
				pdu.setTimezone(tz)
				self.assertEquals(tz, pdu.timezone)

			with self.createUUT() as pdu:
				self.assertEquals(tz, pdu.timezone)

	def testSettingNTPServers(self):
		for svr in [ ('1.1.1.1', '2.2.2.2'), ('3.3.3.3', '4.4.4.4'), ('my.ntp.server', 'foo.bar.baz') ]:
			with self.createUUT() as pdu:
				pdu.enableNTP(svr[0], svr[1])
				self.assertEquals(svr[0], pdu.ntpPrimary)
				self.assertEquals(svr[1], pdu.ntpSecondary)

			with self.createUUT() as pdu:
				self.assertEquals(svr[0], pdu.ntpPrimary)
				self.assertEquals(svr[1], pdu.ntpSecondary)

		with self.createUUT() as pdu:
			pdu.disableNTP()
			self.assertEquals('0.0.0.0', pdu.ntpPrimary)
			self.assertEquals('0.0.0.0', pdu.ntpSecondary)
		with self.createUUT() as pdu:
			self.assertEquals('0.0.0.0', pdu.ntpPrimary)
			self.assertEquals('0.0.0.0', pdu.ntpSecondary)

	def testSettingSNMP(self):
		for cfg in [
				[{ 'community': 'hello', 'permission': 'read-only'}],
				[{ 'community': 'test' , 'permission': 'read-write'}],
				[{ 'community': 'hello', 'permission': 'read-only'}, { 'community': 'readwrite', 'permission' : 'read-write'} ],
			]:
			with self.createUUT() as pdu:
				pdu.setSNMPServers(cfg)
				for n in range(0, len(cfg)):
					self.assertEquals(cfg[n]['community'], pdu.snmp[n]['community'])
					self.assertEquals(cfg[n]['permission'], pdu.snmp[n]['permission'])
			with self.createUUT() as pdu:
				for n in range(0, len(cfg)):
					self.assertEquals(cfg[n]['community'], pdu.snmp[n]['community'])
					self.assertEquals(cfg[n]['permission'], pdu.snmp[n]['permission'])

		with self.createUUT() as pdu:
			pdu.disableSNMP()
			self.assertEquals(0, len(pdu.snmp))
		with self.createUUT() as pdu:
			self.assertEquals(0, len(pdu.snmp))

	def testSettingSNMPTraps(self):
		for cfg in 	[
					[ {'server': '1.1.1.1', 'community': 'public'} ],
					[ {'server': '2.2.2.2', 'community': 'foo'} ],
					[ {'server': 'my.server.here', 'community': 'foo'} ],
					[ {'server': '3.3.3.3', 'community': 'public' }, {'server': '4.4.4.4', 'community': 'private'}  ],
					[ {'server': '4.4.4.4', 'community': 'private'}, {'server': '3.3.3.3', 'community': 'public' }  ],
					[ {'server': '2.2.2.2', 'community': 'foo'} ],
					[ {'server': '1.2.3.4', 'community': 'test'} ]
				]:
			with self.createUUT() as pdu:
				pdu.setSNMPTraps(cfg)
				for n in range(0, len(cfg)):
					self.assertEquals(cfg[n]['community'], pdu.snmpTraps[n]['community'])
					self.assertEquals(cfg[n]['server'], pdu.snmpTraps[n]['server'])
			with self.createUUT() as pdu:
				for n in range(0, len(cfg)):
					self.assertEquals(cfg[n]['community'], pdu.snmpTraps[n]['community'])
					self.assertEquals(cfg[n]['server'], pdu.snmpTraps[n]['server'])

		with self.createUUT() as pdu:
			pdu.disableSNMPTraps()
			self.assertEquals(0, len(pdu.snmpTraps))
		with self.createUUT() as pdu:
			self.assertEquals(0, len(pdu.snmpTraps))

	def testSettingOutletNames(self):
		for cfg in 	[
					[ { 'id': 1, 'name': 'foo' } ],
					[ { 'id': 1, 'name': 'bar' } ],
					[ { 'id': 2, 'name': 'foo' } ],
					[ { 'id': 1, 'name': 'first' }, { 'id': 2, 'name': 'second' } ]
				]:
			with self.createUUT() as pdu:
				for n in cfg:
					pdu.setOutletName(n['id'], n['name'])
				for n in cfg:
					self.assertEquals(n['name'], filter(lambda x: x['id'] == n['id'], pdu.outlets)[0]['name'] )

			with self.createUUT() as pdu:
				for n in cfg:
					self.assertEquals(n['name'], filter(lambda x: x['id'] == n['id'], pdu.outlets)[0]['name'] )

	def testRebootSensing(self):
		# Get to a clean state
		with self.createUUT() as pdu:
			pdu.setTCPParams(IP='1.2.3.4')
			if pdu.requiresReboot():
				pdu.reboot()

		with self.createUUT() as pdu:
			self.assertEquals(False, pdu.requiresReboot())

		# After changing IP address, the PDU will need a reboot.
		with self.createUUT() as pdu:
			self.assertEquals(False, pdu.requiresReboot())
			pdu.setTCPParams(IP='5.6.7.8')
			self.assertEquals(True, pdu.requiresReboot())

		with self.createUUT() as pdu:
			self.assertEquals(True, pdu.requiresReboot())
			pdu.reboot()

		with self.createUUT() as pdu:
			self.assertEquals(False, pdu.requiresReboot())
