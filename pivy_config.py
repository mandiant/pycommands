import re
import binascii
import struct
import string
from immlib import *
from immutils import *

str_regex = r"^([\w\x20\x00\t\\\:\-\.\&\%\$\#\@\!\(\)\*]+)$"

def main(args):
	imm = Debugger()
	regs = imm.getRegs()
	structaddr = regs["ESI"]
	if len(args) > 0:
		structaddr = int(args[0], 16)

	
	imm.log("PI struct address: 0x%08X" % structaddr)
	id = imm.readString(structaddr + int("AFA", 16))
	group = imm.readString(structaddr + int("BF9", 16))
	pw = imm.readMemory(structaddr + int("145", 16), 32)
	
	imm.log("ID: %s" % id)
	imm.log("Group: %s" % group)
	
	match = re.match(str_regex,pw)
	if match is not None:
		pw = string.strip(pw, "\x00")
		imm.log("Password: %s" % pw)
	else:
		imm.log("Password: 0x%s" % (binascii.hexlify(pw)))
		
	mutex = imm.readString(structaddr + int("3FB", 16))
	imm.log("Mutex: %s" % mutex)
	proxy = False
	if imm.readShort(structaddr + int("2C1", 16)) == 1:
		proxy = True
	
	if proxy:
		cnt = 0
		C2offset = int("2C5", 16)
		while True:
			str_len = imm.readMemory(structaddr + C2offset + cnt, 1)
			cnt = cnt + 1
			str_len = struct.unpack('B', str_len)[0]
			domaindata = imm.readMemory(structaddr + C2offset + cnt, str_len)
			
			domain = ""
			for c in domaindata:
				if c != "\x00":
					domain += c
				else:
					break
			cnt = cnt + str_len
			imm.log("C2: %s" % domain)
			version = imm.readMemory(structaddr + C2offset + cnt, 1)
			cnt = cnt + 1
			version = struct.unpack('B', version)[0]
			imm.log("C2 version: %d" % version)
			port = imm.readShort(structaddr + C2offset + cnt)
			cnt = cnt + 2
			imm.log("C2 port: %d" % port)
			if struct.unpack('B', imm.readMemory(structaddr + C2offset + cnt, 1))[0] == 0:
				break
			imm.log("***********")
			
	cnt = 0
	C2offset = int("190", 16)
	while True:
		str_len = imm.readMemory(structaddr + C2offset + cnt, 1)
		cnt = cnt + 1
		str_len = struct.unpack('B', str_len)[0]
		domaindata = imm.readMemory(structaddr + C2offset + cnt, str_len)
		
		domain = ""
		for c in domaindata:
			if c != "\x00":
				domain += c
			else:
				break
		
		cnt = cnt + str_len
		if proxy is True:
			imm.log("Proxy: %s" % domain)
		else:
			imm.log("C2: %s" % domain)
		version = imm.readMemory(structaddr + C2offset + cnt, 1)
		cnt = cnt + 1
		version = struct.unpack('B', version)[0]
		if proxy is True:
			imm.log("Proxy version: %d" % version)
		else:
			imm.log("C2 version: %d" % version)
		port = imm.readShort(structaddr + C2offset + cnt)
		cnt = cnt + 2
		if proxy is True:
			imm.log("Proxy port: %d" % port)
		else:
			imm.log("C2 port: %d" % port)
		if struct.unpack('B', imm.readMemory(structaddr + C2offset + cnt, 1))[0] == 0:
			break
		imm.log("***********")
			
	implant = imm.readString(structaddr + int("12D", 16))
	
	ads = imm.readMemory(structaddr + int("D12", 16), 1)
	ads = struct.unpack('B', ads)[0]
	
	copydir = struct.unpack('B', imm.readMemory(structaddr + int("3F7", 16), 1))[0]
	
	destination = ""
	if copydir == 1:
		destination = "%WINDIR%"
	elif copydir == 2:
		destination = "%WINDIR%\\system32"

	if ads == 1:
		destination += ':'
	elif destination != "":
		destination += '\\' 
	
	if destination != "":
		implant = destination + implant
		imm.log("Implant filename: %s" % implant)
	
	activesetup = struct.unpack('B', imm.readMemory(structaddr + int("3F6", 16), 1))[0]
	if activesetup == 1:
		runkey = imm.readString(structaddr + int("4B3", 16))
		runname = imm.readString(structaddr + int("40F", 16))
		imm.log("Active Setup key: %s" % runkey)
		imm.log("Active Setup value name: %s" % runname)
		
	run = struct.unpack('B', imm.readMemory(structaddr + int("D09", 16), 1))[0]
	if run == 1:
		runname = imm.readString(structaddr + int("E12", 16))
		imm.log("HKLM run value name: %s" % runname)
				
	keylogconf = imm.readMemory(structaddr + int("3FA", 16), 1)
	keylogconf = struct.unpack('B', keylogconf)[0]
	if keylogconf == 1:
		imm.log("Keylogger installed")
		
	if keylogconf == 1:
		keylog = imm.readString(structaddr + int("7B0", 16))
		imm.log("Key stroke log file: %s" % keylog)
	
	return "Complete.."