#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  lib/eapeak/scapylayers/l2.py
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
#  These are layers from an old version of Scapy in which the author
#  made several additions to and built EAPEAK around

from scapy.fields import ByteEnumField, ByteField, ConditionalField, StrField, FlagsField, BitField, StrLenField, FieldListField, ShortField, FieldLenField, IntField
from scapy.packet import Packet

eap_types = {
	1: 'ID',
	2: 'NOTIFICATION',
	3: 'LEGACY NAK',
	4: 'MD5',
	5: 'ONE TIME PASSWORD',
	6: 'GENERIC TOKEN CARD',
	13: 'EAP-TLS',
	17: 'LEAP',
	21: 'EAP-TTLS',
	25: 'PEAP',
	43: 'EAP-FAST',
	254: 'EXPANDED EAP',
}

class EAP(Packet):
	name = 'EAP'
	fields_desc = [
		ByteEnumField('code', 4, {1: 'REQUEST', 2: 'RESPONSE', 3: 'SUCCESS', 4: 'FAILURE'}),
		ByteField('id', 0),
		ShortField('len', None),
		ConditionalField(ByteEnumField('type', 0, eap_types), lambda pkt: pkt.code not in [EAP.SUCCESS, EAP.FAILURE]),  # pylint: disable=undefined-variable
		ConditionalField(StrLenField('identity', '', length_from=lambda pkt: pkt.len - 5), lambda pkt: pkt.code == EAP.RESPONSE and pkt.type == 1),
		ConditionalField(FieldListField('eap_types', [0x00], ByteEnumField('eap_type', 0x00, eap_types), count_from=lambda pkt: pkt.len - 5), lambda pkt: pkt.code == EAP.RESPONSE and pkt.type == 3)
	]
	REQUEST = 1
	RESPONSE = 2
	SUCCESS = 3
	FAILURE = 4
	TYPE_ID = 1
	TYPE_MD5 = 4

	def answers(self, other):
		if isinstance(other, EAP):
			if self.code == self.REQUEST:
				return 0
			elif self.code == self.RESPONSE:
				if (other.code == self.REQUEST) and (other.type == self.type):
					return 1
			elif other.code == self.RESPONSE:
				return 1
		return 0

	def post_build(self, p, pay):
		if self.len is None:
			l = len(p) + len(pay)
			p = p[:2] + chr((l >> 8) & 0xff) + chr(l & 0xff) + p[4:]
		return p + pay

class LEAP(Packet):  # eap type 17
	name = 'LEAP'
	fields_desc = [
	ByteField('version', 1),
	ByteField('reserved', 0),
	FieldLenField('length', None, length_of='data', fmt='B'),
	StrLenField('data', '', length_from=lambda pkt: pkt.length),
	StrField('name', '')
]

class PEAP(Packet):  # eap type 25
	name = 'PEAP'
	fields_desc = [
	FlagsField('flags', 0, 6, ['reserved3', 'reserved2', 'reserved1', 'start', 'fragmented', 'length']),
	BitField('version', 0, 2),
	ConditionalField(IntField('length', 0), lambda pkt: pkt.flags > 31),
]
