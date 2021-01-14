![Brainstorm](https://tryhackme-images.s3.amazonaws.com/room-icons/616a8d84bdacec4150a220e66cb215d2.jpeg)

# [Brainstorm](https://tryhackme.com/room/brainstorm)

## Introduction

This will be my first attempt at a tryhackme walkthrough, and certainly no testimony to my individual skill.  Closer to reality is I'm stubborn as a mule and I detested running a windows VM on a perfectly good linux box.  It may be 2021, and Windows 10 VM images might be free, but I still remember the 90s.

So after applying my new found [buffer overflow skills](https://tryhackme.com/room/bufferoverflowprep), completing the room, and following the walkthroughs kindly created by others ([@TCM](https://www.youtube.com/watch?v=T1-Sds8ZHBU&feature=youtu.be),[@sawinskii](https://github.com/sawinskii/TryHackMe/blob/master/Brainstorm/Brainstorm.pdf), & [@Noxious](https://noxious.tech/posts/Brainstorm/))  I figured I would try to complete the room without a VM and without any scripts.

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

So it is at this point that we arrive at the fork in the road.  Let's spin up WINE and get started disassembling. 

`pacman -S wine`

Wine comes with its own integrated debugger 

