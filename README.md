# Write-up [```NDH2018```](https://lehack.org/)  
Privilege escalation challenges created for [Harmonie-Technologie](https://www.harmonie-technologie.com/) exhibition stand @ NDH16 (Paris)

## Index

| Title        | Description   |
| ------------- |:-------------|
| [Challenge rules](#Challenge-rules)  | VM link and Rules |
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

## Challenge rules  
The vulnerable virtual machine can be downloaded [here](https://www.):
* 32 bits
* 7 Go
* md5sum: xxxxxx

Here are the rules:
* First, we SSH as `level1` into ```/wargames/level1/```
* Our goal is to elevate our privileges as level1_OK to read the ```validation/flag``` file.
* This flag enables us to SSH as `level2` into ```/wargames/level2```, etc.
* The main goal is to read `level10`'s ```validation/flag```.

During NDH2018, VMs kicked challengers after 60 minutes and passwords were re-generated.

## Challenge 1
We connect to level1:
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
.bash_history looks not empty. Let's cat it.

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

It seems that level1_OK tried to su, but due to keying error, he typed his password when not asked. His password is now saved into .bash_history like all commands he types. Armed with this password, we can SSH as level1_OK and cat the flag:

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

![](http://poc-server.com/write-ups/h1/MIME_Accept.gif)

## The end  
Thanks for reading this far.  
I hope you learned something from it, but more importantly; I hope you enjoyed it.  
# 
*Created by [Lyderic 'aas' Lefebvre](https://www.linkedin.com/in/lydericlefebvre/)*
