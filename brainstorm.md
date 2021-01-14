![Brainstorm](https://tryhackme-images.s3.amazonaws.com/room-icons/616a8d84bdacec4150a220e66cb215d2.jpeg)

# [Brainstorm](https://tryhackme.com/room/brainstorm)

## Introduction

This will be my first attempt at a tryhackme walkthrough, and certainly no testimony to my individual skill.  Closer to reality is I'm stubborn as a mule and I detested running a windows VM on a perfectly good linux box.  It may be 2021, and Windows 10 VM images might be free, but I still remember the 90s.

So after applying my new found [buffer overflow skills](https://tryhackme.com/room/bufferoverflowprep), completing the room, and following the walkthroughs kindly created by others ([@TCM](https://www.youtube.com/watch?v=T1-Sds8ZHBU&feature=youtu.be),[@sawinskii](https://github.com/sawinskii/TryHackMe/blob/master/Brainstorm/Brainstorm.pdf), & [@Noxious](https://noxious.tech/posts/Brainstorm/))  I figured I would try to complete the room without a VM and without any scripts.

## Let's get started

Task 1 is to simply deploy the machine and do a bit of reconnaissance.  Don't forget your `-Pn` flag as the machine doesn't respond to ICMP:

`nmap -A -vv -oN nmap.txt -Pn 10.10.51.160`
