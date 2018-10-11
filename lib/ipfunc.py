#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  lib/ipfunc.py
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are
#  met:
#
#  * Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#  * Redistributions in binary form must reproduce the above
#    copyright notice, this list of conditions and the following disclaimer
#    in the documentation and/or other materials provided with the
#    distribution.
#  * Neither the name of the project nor the names of its
#    contributors may be used to endorse or promote products derived from
#    this software without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

from fcntl import ioctl
from socket import socket, AF_INET, SOCK_DGRAM
from struct import pack

__doc__ = 'Distributed as part of CORI, http://sourceforge.net/projects/cori-python/\n\nThis module contains misc. ip related functions.'  # pylint: disable=redefined-builtin
__version__ = '1.8'

numbers = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '0']


def sanitizeMAC(addr, ciscoFormat=False):
	"""
	This function will return True if the string passed to it looks like a real MAC address.
	ciscoFormat defines whether to expect Cisco\'s xxxx.xxxx.xxxx format.
	"""
	if ciscoFormat:
		char = '.'
		len0 = 3
		len1 = 4
		top = 65536
	else:
		char = ':'
		len0 = 6
		len1 = 2
		top = 256
	addr = addr.split(char)
	if len(addr) != len0:
		return False
	for part in addr:
		if len(part) != len1:
			return False
		try:
			if not int(part, 16) < top:
				return False
		except ValueError:
			return False
	return True

def getHwAddr(ifname):
	"""
	Return the MAC address associated with a network interface, available only on Linux
	"""
	s = socket(AF_INET, SOCK_DGRAM)
	info = ioctl(s.fileno(), 0x8927, pack('256s', ifname[:15]))
	return ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]
