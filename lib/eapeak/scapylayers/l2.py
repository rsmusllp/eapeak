#!/usr/bin/env python
#
# -*- coding: utf-8 -*-
#
#  lib/eapeak/scapylayers/l2.py
#
#  These are layers from an old version of Scapy in which the author
#  made several additions to and built EAPEAK around

import os,struct,time

#External imports
from scapy.base_classes import Net
from scapy.config import conf
from scapy.packet import *
from scapy.ansmachine import *
from scapy.plist import SndRcvList
from scapy.fields import *
from scapy.sendrecv import srp,srp1,srpflood
from scapy.arch import LOOPBACK_NAME,get_if_hwaddr,pcapdnet


eap_types = {	1:"ID",
				2:"NOTIFICATION",
				3:"LEGACY NAK",
				4:"MD5",
				5:"ONE TIME PASSWORD",
				6:"GENERIC TOKEN CARD",
				13:"EAP-TLS",
				17:"LEAP",
				21:"EAP-TTLS",
				25:"PEAP",
				43:"EAP-FAST",
				254:"EXPANDED EAP"
			}

class EAP(Packet):
    name = "EAP"
    fields_desc = [ ByteEnumField("code", 4, { 1:"REQUEST", 2:"RESPONSE", 3:"SUCCESS", 4:"FAILURE" }),
                    ByteField("id", 0),
                    ShortField("len",None),
                    ConditionalField(ByteEnumField("type",0, eap_types), lambda pkt:pkt.code not in [EAP.SUCCESS, EAP.FAILURE]),
                    ConditionalField(StrLenField("identity", "", length_from=lambda pkt:pkt.len - 5), lambda pkt: pkt.code == EAP.RESPONSE and pkt.type == 1),
                    ConditionalField(FieldListField("eap_types", [0x00], ByteEnumField("eap_type", 0x00, eap_types), count_from = lambda pkt:pkt.len - 5), lambda pkt: pkt.code == EAP.RESPONSE and pkt.type == 3)
                                     ]
    
    REQUEST = 1
    RESPONSE = 2
    SUCCESS = 3
    FAILURE = 4
    TYPE_ID = 1
    TYPE_MD5 = 4
    def answers(self, other):
        if isinstance(other,EAP):
            if self.code == self.REQUEST:
                return 0
            elif self.code == self.RESPONSE:
                if ( (other.code == self.REQUEST) and
                     (other.type == self.type) ):
                    return 1
            elif other.code == self.RESPONSE:
                return 1
        return 0
    
    def post_build(self, p, pay):
        if self.len is None:
            l = len(p)+len(pay)
            p = p[:2]+chr((l>>8)&0xff)+chr(l&0xff)+p[4:]
        return p+pay
                         
class LEAP(Packet):  # eap type 17
    name = "LEAP"
    fields_desc = [ ByteField("version", 1),
                    ByteField("reserved", 0),
                    FieldLenField("length", None, length_of="data", fmt="B"),
                    StrLenField("data", "", length_from=lambda pkt:pkt.length),
                    StrField("name", "")
                ]

class PEAP(Packet):  # eap type 25
    name = "PEAP"
    fields_desc = [ FlagsField("flags", 0, 6, ['reserved3', 'reserved2', 'reserved1', 'start', 'fragmented', 'length']),
                    BitField("version", 0, 2),
                    ConditionalField(IntField("length", 0), lambda pkt:pkt.flags > 31),
                ]
