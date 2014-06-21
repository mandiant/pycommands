# Copyright (c) 2014 FireEye, Inc. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.


from immlib import *
from immutils import *
import re
import binascii
import struct
import string
findconfig = r"\x55\x8b\xec\x6a\x00\x6a\x00\x6a\x00\x53\x56\x57\x8b\xd8\x8b\x3d(.{4})\x33\xc0\x55"
c2ptn = r".+\..+:[\d]+"
def main(args):
	imm = Debugger()
	configptr = None
	for page in imm.getMemoryPages():
		if page.getSize() == 0x62000:
			imm.log("checking pages: %08X" % page.getBaseAddress())
			mem = page.getMemory()
			match = re.search(findconfig,mem)
			if not match:
				continue
			ptr = struct.unpack('<I',match.group(1))[0]
			#imm.log("%08X" % ptr)
			configptr = imm.readLong(ptr)
			ptr = imm.readLong(configptr)
			c2 = imm.readString(ptr)
			if re.match(c2ptn,c2):
				imm.log("Config address: %08X" % configptr)
				imm.log("Build config func address: %08X" % (match.start(0) + page.getBaseAddress()))
				installpathptr = imm.readLong(match.start(0) + page.getBaseAddress() + 0x9B)
				installpathptr = imm.readLong(installpathptr)
				installpathptr = imm.readLong(installpathptr)
				break
	if configptr != None:
		c2configptr = configptr
		while re.match(c2ptn,c2):
			imm.log("C2: %s" % c2)
			c2configptr += 4
			ptr = imm.readLong(c2configptr)
			if ptr == 0:
				break
			c2 = imm.readString(ptr)
		
		configptr += 80
		imm.log("ID: %s" % imm.readString(imm.readLong(configptr)))
		configptr += 4
		imm.log("Password: %s" % imm.readString(imm.readLong(configptr)))
		configptr += 0xA4
		imm.log("Mutex: %s" % imm.readString(imm.readLong(configptr)))
		imm.log("Implant Path: %s" % imm.readString(installpathptr))
	return "Complete.."