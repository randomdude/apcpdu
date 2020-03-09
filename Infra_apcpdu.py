#!/usr/bin/python

import sys
import pexpect
import pexpect.fdpexpect
import serial
import time

class Infra_apcpdu:
	def __init__(self, serialport, username, password, extraLogging=False):
		self.extraLogging = extraLogging
		self.username = username
		self.password = password
#		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#		self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.log("Opening serial port %s" % serialport)
		self.ser = serial.Serial()
		self.ser.baudrate = 9600
		self.ser.stopbits=serial.STOPBITS_ONE
		self.ser.xonxoff=0
		self.ser.port=serialport
		self.ser.open()
		self.log("Port open.")

		# Normally this timeout can be very small, but if the PDU has just booted then it'll take longer to
		# respond, and so the longer timeout is neccessary.
		self.exp = pexpect.fdpexpect.fdspawn(self.ser, timeout=5)

		if self.extraLogging:
			# Direct the stream to stdout so we can debug it better
			self.exp.logfile = sys.stdout

		self.logon()

		# Get TCP/IP parameters. Be careful not to inadvertantly match 'ipv4 address' which is a substring of other
		# things (like 'active ipv4 address', which is not what we want).
		self.exp.send('tcpip\r')
		self.expectSuccess()
		self.IP = self.waitAndGetGroup("\n  IPv4 Address:\t*([0-9\.]*)\r")
		self.subnetMask = self.waitAndGetGroup("\n  Subnet Mask:\t*([0-9\.]*)\r")
 		self.gateway = self.waitAndGetGroup("\n  Gateway:\t*([0-9\.]*)\r")
		self.MACAddress = self.waitAndGetGroup("\n  MAC Address:\t*([0-9a-zA-Z ]*)\r").replace(' ', ':')
		self.domainName = self.waitAndGetGroup("\n  Domain Name:\t*([^\r]*)\r")
		self.hostname = self.waitAndGetGroup("\n  Host Name:\t*([^\r]*)\r")
		self.vlan = None
		self.exp.expect("apc>")

		# Get outlet names
		self.outlets = []
		self.exp.send('olName all\r')
		while True:
			res = self.exp.expect(["E000: Success","\n *([0-9]*): ([^\r]*)\r"])
			if res == 0:
				# Command has finished, we've got all the outlets.
				break
			else:
				# An outlet!
				id = self.exp.match.group(1).strip()
				name = self.exp.match.group(2).strip()
				self.outlets.append( { 'id': int(id), 'name': name } )
		self.exp.expect("apc>")

		# NTP
		self.exp.send('ntp\r')
		self.expectSuccess()
		NTPEnabled = self.waitAndGetGroup("\nNTP status: (Disabled|Enabled)\r")
		if NTPEnabled == 'Disabled':
			self.log("NTP disabled.")
			self.ntpPrimary   = '0.0.0.0'
			self.ntpSecondary = '0.0.0.0'
		else:
			self.log("NTP enabled, querying..")
			self.ntpPrimary   = self.waitAndGetGroup("\nActive Primary NTP Server:\t*([^\r]*)\r")
			self.ntpSecondary = self.waitAndGetGroup("\nActive Secondary NTP Server:\t*([^\r]*)\r")
		self.exp.expect("apc>")

		self.exp.send('date\r')
		self.expectSuccess()
		self.timezone = self.waitAndGetGroup("\nTime Zone:\t*([^\r]*)\r")
		self.exp.expect("apc>")

		# SNMP
		self.snmp = [ ]
		self.exp.send('snmp\r')
		self.expectSuccess()
		SNMPEnabled = self.waitAndGetGroup(" *SNMPv1: *(enabled|disabled)\r")
		if SNMPEnabled == 'disabled':
			self.log("SNMP disabled.")
		else:
			self.log("SNMP enabled, querying..")
			for a in range(1, 5):
				comm = self.waitAndGetGroup("Community:[ \t]*([^\r]*)\r")
				type = self.waitAndGetGroup("Access Type:\t*(read|write|disabled)\r")
				if type == 'disabled':
					continue
				elif type == 'read':
					type = 'read-only'
				elif type == 'write':
					type = 'read-write'
				else:
					raise Exception("Unrecognised SNMP permission '%s'" % type)
				self.snmp.append( { 'community': comm, 'permission': type } )
		self.exp.expect("apc>")

		# SNMP traps
		self.snmpTraps = []
		self.exp.send('snmptrap\r')
		if self.exp.expect([ "No trap receivers configured\r", "Index:"], timeout=2) == 0:
			self.log("No SNMP trap recievers.")
			self.exp.expect("apc>")
		else:
			while True:
				IP = self.waitAndGetGroup("Receiver IP:[ \t]*([^\r]*)\r")	# This might actually be a domain name
				comm = self.waitAndGetGroup("Community:[ \t]*([^\r]*)\r")
				generation = self.waitAndGetGroup("Generation:[ \t]*(enabled|disabled)\r")
				generation_traps = self.waitAndGetGroup("Auth Traps:[ \t]*(enabled|disabled)\r")
				if generation == 'enabled' or generation_traps == 'enabled':
					self.snmpTraps.append( { 'server': IP, 'community': comm} )

				# A command prompt terminates our list.
				if (self.exp.expect(["Index:", "apc>"], timeout=2)) == 1:
					break

		# TODO: does the PDU support remote syslog? The documentation talks about it, and how to access it from the web UI, but I
		# can't find a way to access it from the CLI.
		self.syslog = []

		# The PDU isn't a switch, silly.
		self.interfaces = []

	def expectSuccess(self, timeout = 1):
		self.exp.expect("E([0-9]*): ([^\r]*)\r", timeout)
		if self.exp.match.group(1).strip() != "000":
			raise Exception("Expected success but got %s" % self.exp.match.group(2).strip())

	def expectSuccessOr(self, toFind, timeout = 1):
		patterns = [ "E([0-9]*): ([^\r]*)\r" ]
		patterns.extend(toFind)
		toRet = self.exp.expect(patterns, timeout)
		if toRet == 0:
			if self.exp.match.group(1).strip() != "000":
				raise Exception("Expected success but got %s" % self.exp.match.group(2).strip())
		return toRet

	def logon(self):
		# Hit return. We should see either a login prompt, or a regular "apc>" prompt if the device is already
		# logged in by a previous session.
		self.ser.reset_input_buffer()
		self.exp.send("\r")
		self.log("Waiting for login prompt..")
		while True:
			try:
				if (self.exp.expect([ "User Name : ", "apc>" ], timeout=1) == 1):
					self.log("Device is already logged in, continuing")
					isLoggedIn = True
				else:
					isLoggedIn = False
				break
			except pexpect.exceptions.TIMEOUT:
				self.log(".. no login prompt, hitting enter to see if one appears")
				self.exp.send("\r")
				continue
		if isLoggedIn == False:
			# We must now proceed to log in.
			self.log("Logging in..")
			self.exp.send(self.username + '\r')
			self.exp.expect("Password  : ")
			self.exp.send(self.password + '\r')
			# If the login fails, we'll be presented with the 'User Name : ' prompt again.
			if (self.exp.expect([ "apc>", "User Name : "], timeout=2) == 1):
				raise Exception("Login failed")
			self.log("Logged into device OK.")

		# Strangely, some specifc commands (such as olname) will sometimes fail with an 'E101: Command Not Found', immediately after rebooting
		# the PDU. Wait until this command can succeed before returning.
		for cmd in ('olname 1\r', 'ntp', 'snmp', 'snmptrap'):
			while True:
				self.exp.send('olname 1\r')
				res = self.exp.expect(["E000: Success", "E101: Command Not Found"], 5)
				if res == 0:
					break
				time.sleep(1)

		self.log("All PDU functions available.")


	def setOutletName(self, olID, newname):
		toChange = filter(lambda x: x['id'] == olID, self.outlets)
		if len(toChange) == 0:
			raise Exception ("Outlet '%d' not found" % olID)
		toChange[0]['name'] = newname
		self.exp.send('olname %d %s\r' % (olID, newname))
		self.expectSuccess()
		self.exp.expect("apc>")

	def waitAndGetGroup(self, regex, groupindex=1):
		# wait for a specified text and return the specified group from the regex.
		self.exp.expect(regex)
		return self.exp.match.group(groupindex).strip()

	def setSNMPTraps(self, traplist):
		trapIdx = 1
		for trapInfo in traplist:
			# Weirdly, the APC PDU requires that the SNMP trap servers, if specified by name, contain at least one '.' character.
			# If we don't meet this requirement, the trap server is silently not-set. Weird, huh?
			if '.' not in trapInfo['server']:
				raise Exception("APC PDU requires that SNMP trap servers are specified as IP addreses or domain names containing at least one '.' character")

			self.exp.send("snmptrap -c%d %s -r%d %s -t%d snmpV1 -g%d enable -a%d enable\r" % (trapIdx, trapInfo['community'], trapIdx, trapInfo['server'], trapIdx, trapIdx, trapIdx))
			self.expectSuccess()
			self.exp.expect("apc>")
			trapIdx = trapIdx + 1
		self.snmpTraps = traplist

	def disableSNMPTraps(self):
		# Find how many traps destinations are configured, and disable them all. I can't find a way to
		# delete them, as such.
		self.exp.send('snmptrap\r')
		if self.exp.expect([ "No trap receivers configured\r", "Index:"]) == 0:
			self.traps = []
			self.exp.expect("apc>")
			return
		trapCount = 1
		while True:
			if (self.exp.expect(["Index:", "apc>"]) == 1):
				break
			trapCount = trapCount + 1
		# Disable each in turn.
		for n in range(1, trapCount + 1):
			self.exp.send("snmptrap -g%d disable -a%d disable\r" % (n, n))
			self.expectSuccess()
			self.exp.expect("apc>")
		self.snmpTraps = []

	def setSNMPServers(self, serverlist):
		for a in range(0, len(serverlist)):
			if serverlist[a]['permission'] == 'read-only':
				priv = 'read'
			elif serverlist[a]['permission'] == 'read-write':
				priv = 'write'
			else:
				raise Exception("unknown SNMP priv level '%s'" % serverlist[a]['permission'])
			self.exp.send("snmp -S enable -c%d %s -a%d %s \r" % (a + 1, serverlist[a]['community'], a + 1, priv))
			self.expectSuccess()
			self.exp.expect("apc>")
		self.snmp = serverlist

	def disableSNMP(self):
		self.exp.send("snmp -S disable\r")
		self.exp.expect("E002: Success")	# reboot required
		self.exp.expect("apc>")
		self.snmp = []

	def enableNTP(self, primary, secondary='0.0.0.0'):
		# Weirdly, the APC PDU requires that the NTP servers, if specified by name, contain at least one '.' character.
		# If we don't meet this requirement, the NTP server is silently not-set. Weird, huh?
		if '.' not in primary or '.' not in secondary:
			raise Exception("APC PDU requires that NTP servers are specified as IP addreses or domain names containing at least one '.' character")

		self.exp.send("ntp -p %s -s %s -e enable -u\r" % (primary, secondary))
		self.expectSuccess()
		self.exp.expect("apc>")
		self.ntpPrimary = primary
		self.ntpSecondary = secondary

	def disableNTP(self):
		self.exp.send("ntp -e disable\r")
		self.expectSuccess()
		self.exp.expect("apc>")
		self.ntpPrimary = '0.0.0.0'
		self.ntpSecondary = '0.0.0.0'

	def setTimezone(self, newTZ):
		# the 'date' command takes '-z' to specify timezone, and a few other parameters we don't use, which set the
		# time/date format and the time/date itself.
		self.exp.send("date -z %s\r" % newTZ)
		self.expectSuccess()
		self.exp.expect("apc>")
		self.timezone = newTZ

	def setTCPParams(self, IP=None, subnetMask=None, gateway=None, domainName=None, hostname=None, vlan=None):
		if vlan != None:
			raise Exception("APC PDU does not support vlan tagging")
		if IP == None:
			IP = self.IP
		if subnetMask == None:
			subnetMask = self.subnetMask
		if gateway == None:
			gateway = self.gateway
		if domainName == None:
			domainName = self.domainName
		if hostname == None:
			hostname = self.hostname

		# The 'tcpip' command takes:
		# -S [enable|disable] -i <IP> -s <subnet mask> -g <gateway> -d <domain name> -h <hostname>
		self.exp.send("tcpip -S enable -i %s -s %s -g %s -d %s -h %s\r" % (IP, subnetMask, gateway, domainName, hostname) )
		self.expectSuccess(timeout=5)
		self.exp.expect("apc>")
		self.IP=IP
		self.subnetMask=subnetMask
		self.gateway=gateway
		self.domainName=domainName
		self.hostname=hostname

	def requiresReboot(self):
		# If the device requres a reboot, it will tell us so every time we hit return.
		# Otherwise, it'll just send a prompt.
		self.exp.send("\r")
		if self.exp.expect(["apc>", "Reboot required for change to take effect"]) == 1:
			return True
		return False

	def reboot(self):
		self.exp.send("reboot\r")
		self.exp.expect("Enter 'YES' to continue or <ENTER> to cancel : ")
		self.exp.send("YES\r")
		self.exp.expect("Rebooting...")
		# Wait until the device stops responding before we try to log back on.
		while (True):
			try:
				self.exp.send("\r")
				self.exp.expect("apc>", 1)
				time.sleep(1)
				continue
			except pexpect.exceptions.TIMEOUT:
				break
		self.log("PDU has started rebooting.")
		self.logon()
		self.log("PDU is up.")

	def __enter__(self):
		return self

	def __exit__(self, a, b, c):
		self.ser.close()

	def log(self, msg):
		if self.extraLogging:
			print msg.replace("\r", "\n")


