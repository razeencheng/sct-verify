#!/usr/bin/env python

# Signed Certificate Timestamp TLS extension verifier  
# Copyright (c) 2015 Pier Carlo Chiodi - http://www.pierky.com
#
# https://github.com/pierky/sct-verify

import sys
import subprocess
import base64
import struct
import os

try:
  OPENSSL_PATH = os.environ["OPENSSL_PATH"]
except:
  OPENSSL_PATH = "openssl"

LOGS = [
   
		{ "Name" : "Google 'Argon2018' log",
		"Key" : "-----BEGIN PUBLIC KEY-----\n"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE0gBVBa3VR7QZu82V+ynXWD14JM3ORp37MtRxTmACJV5ZPtfUA7htQ2hofuigZQs+bnFZkje+qejxoyvk2Q1VaA==\n"
		"-----END PUBLIC KEY-----",
		"LogID": "pFASaQVaFVReYhGrN7wQP2KuVXakXksXFEU+GyIQaiU=" },
		
		{ "Name" : "Google 'Argon2019' log",
		"Key" : "-----BEGIN PUBLIC KEY-----\n"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEI3MQm+HzXvaYa2mVlhB4zknbtAT8cSxakmBoJcBKGqGwYS0bhxSpuvABM1kdBTDpQhXnVdcq+LSiukXJRpGHVg==\n"
		"-----END PUBLIC KEY-----",
		"LogID": "Y/Lbzeg7zCzPC3KEJ1drM6SNYXePvXWmOLHHaFRL2I0=" },
		
		{ "Name" : "Google 'Argon2020' log",
		"Key" : "-----BEGIN PUBLIC KEY-----\n"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6Tx2p1yKY4015NyIYvdrk36es0uAc1zA4PQ+TGRY+3ZjUTIYY9Wyu+3q/147JG4vNVKLtDWarZwVqGkg6lAYzA==\n"
		"-----END PUBLIC KEY-----",
		"LogID": "sh4FzIuizYogTodm+Su5iiUgZ2va+nDnsklTLe+LkF4=" },
		
		{ "Name" : "Google 'Argon2021' log",
		"Key" : "-----BEGIN PUBLIC KEY-----\n"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETeBmZOrzZKo4xYktx9gI2chEce3cw/tbr5xkoQlmhB18aKfsxD+MnILgGNl0FOm0eYGilFVi85wLRIOhK8lxKw==\n"
		"-----END PUBLIC KEY-----",
		"LogID": "9lyUL9F3MCIUVBgIMJRWjuNNExkzv98MLyALzE7xZOM=" },
		
		{ "Name" : "Google 'Aviator' log",
		"Key" : "-----BEGIN PUBLIC KEY-----\n"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1/TMabLkDpCjiupacAlP7xNi0I1JYP8bQFAHDG1xhtolSY1l4QgNRzRrvSe8liE+NPWHdjGxfx3JhTsN9x8/6Q==\n"
		"-----END PUBLIC KEY-----",
		"LogID": "aPaY+B9kgr46jO65KB1M/HFRXWeT1ETRCmesu09P+8Q=" },
		
		{ "Name" : "Google 'Icarus' log",
		"Key" : "-----BEGIN PUBLIC KEY-----\n"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETtK8v7MICve56qTHHDhhBOuV4IlUaESxZryCfk9QbG9co/CqPvTsgPDbCpp6oFtyAHwlDhnvr7JijXRD9Cb2FA==\n"
		"-----END PUBLIC KEY-----",
		"LogID": "KTxRllTIOWW6qlD8WAfUt2+/WHopctykwwz05UVH9Hg=" },
		
		{ "Name" : "Google 'Pilot' log",
		"Key" : "-----BEGIN PUBLIC KEY-----\n"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfahLEimAoz2t01p3uMziiLOl/fHTDM0YDOhBRuiBARsV4UvxG2LdNgoIGLrtCzWE0J5APC2em4JlvR8EEEFMoA==\n"
		"-----END PUBLIC KEY-----",
		"LogID": "pLkJkLQYWBSHuxOizGdwCjw1mAT5G9+443fNDsgN3BA=" },
		
		{ "Name" : "Google 'Rocketeer' log",
		"Key" : "-----BEGIN PUBLIC KEY-----\n"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIFsYyDzBi7MxCAC/oJBXK7dHjG+1aLCOkHjpoHPqTyghLpzA9BYbqvnV16mAw04vUjyYASVGJCUoI3ctBcJAeg==\n"
		"-----END PUBLIC KEY-----",
		"LogID": "7ku9t3XOYLrhQmkfq+GeZqMPfl+wctiDAMR7iXqo/cs=" },
		
		{ "Name" : "Google 'Skydiver' log",
		"Key" : "-----BEGIN PUBLIC KEY-----\n"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEmyGDvYXsRJsNyXSrYc9DjHsIa2xzb4UR7ZxVoV6mrc9iZB7xjI6+NrOiwH+P/xxkRmOFG6Jel20q37hTh58rA==\n"
		"-----END PUBLIC KEY-----",
		"LogID": "u9nfvB+KcbWTlCOXqpJ7RzhXlQqrUugakJZkNo4e0YU=" },
		
		{ "Name" : "Cloudflare 'Nimbus2018' Log",
		"Key" : "-----BEGIN PUBLIC KEY-----\n"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAsVpWvrH3Ke0VRaMg9ZQoQjb5g/xh1z3DDa6IuxY5DyPsk6brlvrUNXZzoIg0DcvFiAn2kd6xmu4Obk5XA/nRg==\n"
		"-----END PUBLIC KEY-----",
		"LogID": "23Sv7ssp7LH+yj5xbSzluaq7NveEcYPHXZ1PN7Yfv2Q=" },
		
		{ "Name" : "Cloudflare 'Nimbus2019' Log",
		"Key" : "-----BEGIN PUBLIC KEY-----\n"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEkZHz1v5r8a9LmXSMegYZAg4UW+Ug56GtNfJTDNFZuubEJYgWf4FcC5D+ZkYwttXTDSo4OkanG9b3AI4swIQ28g==\n"
		"-----END PUBLIC KEY-----",
		"LogID": "dH7agzGtMxCRIZzOJU9CcMK//V5CIAjGNzV55hB7zFY=" },
		
		{ "Name" : "Cloudflare 'Nimbus2020' Log",
		"Key" : "-----BEGIN PUBLIC KEY-----\n"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE01EAhx4o0zPQrXTcYjgCt4MVFsT0Pwjzb1RwrM0lhWDlxAYPP6/gyMCXNkOn/7KFsjL7rwk78tHMpY8rXn8AYg==\n"
		"-----END PUBLIC KEY-----",
		"LogID": "Xqdz+d9WwOe1Nkh90EngMnqRmgyEoRIShBh1loFxRVg=" },
		
		{ "Name" : "Cloudflare 'Nimbus2021' Log",
		"Key" : "-----BEGIN PUBLIC KEY-----\n"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExpon7ipsqehIeU1bmpog9TFo4Pk8+9oN8OYHl1Q2JGVXnkVFnuuvPgSo2Ep+6vLffNLcmEbxOucz03sFiematg==\n"
		"-----END PUBLIC KEY-----",
		"LogID": "RJRlLrDuzq/EQAfYqP4owNrmgr7YyzG1P9MzlrW2gag=" },
		
		{ "Name" : "DigiCert Log Server",
		"Key" : "-----BEGIN PUBLIC KEY-----\n"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAkbFvhu7gkAW6MHSrBlpE1n4+HCFRkC5OLAjgqhkTH+/uzSfSl8ois8ZxAD2NgaTZe1M9akhYlrYkes4JECs6A==\n"
		"-----END PUBLIC KEY-----",
		"LogID": "VhQGmi/XwuzT9eG9RLI+x0Z2ubyZEVzA75SYVdaJ0N0=" },
		
		{ "Name" : "DigiCert Log Server 2",
		"Key" : "-----BEGIN PUBLIC KEY-----\n"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzF05L2a4TH/BLgOhNKPoioYCrkoRxvcmajeb8Dj4XQmNY+gxa4Zmz3mzJTwe33i0qMVp+rfwgnliQ/bM/oFmhA==\n"
		"-----END PUBLIC KEY-----",
		"LogID": "h3W/51l8+IxDmV+9827/Vo1HVjb/SrVgwbTq/16ggw8=" },
		
		{ "Name" : "DigiCert Yeti2018 Log",
		"Key" : "-----BEGIN PUBLIC KEY-----\n"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESYlKFDLLFmA9JScaiaNnqlU8oWDytxIYMfswHy9Esg0aiX+WnP/yj4O0ViEHtLwbmOQeSWBGkIu9YK9CLeer+g==\n"
		"-----END PUBLIC KEY-----",
		"LogID": "wRZK4Kdy0tQ5LcgKwQdw1PDEm96ZGkhAwfoHUWT2M2A=" },
		
		{ "Name" : "DigiCert Yeti2019 Log",
		"Key" : "-----BEGIN PUBLIC KEY-----\n"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEkZd/ow8X+FSVWAVSf8xzkFohcPph/x6pS1JHh7g1wnCZ5y/8Hk6jzJxs6t3YMAWz2CPd4VkCdxwKexGhcFxD9A==\n"
		"-----END PUBLIC KEY-----",
		"LogID": "4mlLribo6UAJ6IYbtjuD1D7n/nSI+6SPKJMBnd3x2/4=" },
		
		{ "Name" : "DigiCert Yeti2020 Log",
		"Key" : "-----BEGIN PUBLIC KEY-----\n"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEURAG+Zo0ac3n37ifZKUhBFEV6jfcCzGIRz3tsq8Ca9BP/5XUHy6ZiqsPaAEbVM0uI3Tm9U24RVBHR9JxDElPmg==\n"
		"-----END PUBLIC KEY-----",
		"LogID": "8JWkWfIA0YJAEC0vk4iOrUv+HUfjmeHQNKawqKqOsnM=" },
		
		{ "Name" : "DigiCert Yeti2021 Log",
		"Key" : "-----BEGIN PUBLIC KEY-----\n"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6J4EbcpIAl1+AkSRsbhoY5oRTj3VoFfaf1DlQkfi7Rbe/HcjfVtrwN8jaC+tQDGjF+dqvKhWJAQ6Q6ev6q9Mew==\n"
		"-----END PUBLIC KEY-----",
		"LogID": "XNxDkv7mq0VEsV6a1FbmEDf71fpH3KFzlLJe5vbHDso=" },
		
		{ "Name" : "DigiCert Yeti2022 Log",
		"Key" : "-----BEGIN PUBLIC KEY-----\n"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEn/jYHd77W1G1+131td5mEbCdX/1v/KiYW5hPLcOROvv+xA8Nw2BDjB7y+RGyutD2vKXStp/5XIeiffzUfdYTJg==\n"
		"-----END PUBLIC KEY-----",
		"LogID": "IkVFB1lVJFaWP6Ev8fdthuAjJmOtwEt/XcaDXG7iDwI=" },
		
		{ "Name" : "Symantec log",
		"Key" : "-----BEGIN PUBLIC KEY-----\n"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEluqsHEYMG1XcDfy1lCdGV0JwOmkY4r87xNuroPS2bMBTP01CEDPwWJePa75y9CrsHEKqAy8afig1dpkIPSEUhg==\n"
		"-----END PUBLIC KEY-----",
		"LogID": "3esdK3oNT6Ygi4GtgWhwfi6OnQHVXIiNPRHEzbbsvsw=" },
		
		{ "Name" : "Symantec 'Vega' log",
		"Key" : "-----BEGIN PUBLIC KEY-----\n"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6pWeAv/u8TNtS4e8zf0ZF2L/lNPQWQc/Ai0ckP7IRzA78d0NuBEMXR2G3avTK0Zm+25ltzv9WWis36b4ztIYTQ==\n"
		"-----END PUBLIC KEY-----",
		"LogID": "vHjh38X2PGhGSTNNoQ+hXwl5aSAJwIG08/aRfz7ZuKU=" },
		
		{ "Name" : "Symantec 'Sirius' log",
		"Key" : "-----BEGIN PUBLIC KEY-----\n"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEowJkhCK7JewN47zCyYl93UXQ7uYVhY/Z5xcbE4Dq7bKFN61qxdglnfr0tPNuFiglN+qjN2Syxwv9UeXBBfQOtQ==\n"
		"-----END PUBLIC KEY-----",
		"LogID": "FZcEiNe5l6Bb61JRKt7o0ui0oxZSZBIan6v71fha2T8=" },
		
		{ "Name" : "Certly.IO log",
		"Key" : "-----BEGIN PUBLIC KEY-----\n"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAECyPLhWKYYUgEc+tUXfPQB4wtGS2MNvXrjwFCCnyYJifBtd2Sk7Cu+Js9DNhMTh35FftHaHu6ZrclnNBKwmbbSA==\n"
		"-----END PUBLIC KEY-----",
		"LogID": "zbUXm3/BwEb+6jETaj+PAC5hgvr4iW/syLL1tatgSQA=" },
		
		{ "Name" : "Izenpe log",
		"Key" : "-----BEGIN PUBLIC KEY-----\n"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJ2Q5DC3cUBj4IQCiDu0s6j51up+TZAkAEcQRF6tczw90rLWXkJMAW7jr9yc92bIKgV8vDXU4lDeZHvYHduDuvg==\n"
		"-----END PUBLIC KEY-----",
		"LogID": "dGG0oJz7PUHXUVlXWy52SaRFqNJ3CbDMVkpkgrfrQaM=" },
		
		{ "Name" : "WoSign log",
		"Key" : "-----BEGIN PUBLIC KEY-----\n"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzBGIey1my66PTTBmJxklIpMhRrQvAdPG+SvVyLpzmwai8IoCnNBrRhgwhbrpJIsO0VtwKAx+8TpFf1rzgkJgMQ==\n"
		"-----END PUBLIC KEY-----",
		"LogID": "QbLcLonmPOSvG6e7Kb9oxt7m+fHMBH4w3/rjs7olkmM=" },
		
		{ "Name" : "Venafi log",
		"Key" : "-----BEGIN PUBLIC KEY-----\n"
		"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAolpIHxdSlTXLo1s6H1OCdpSj/4DyHDc8wLG9wVmLqy1lk9fz4ATVmm+/1iN2Nk8jmctUKK2MFUtlWXZBSpym97M7frGlSaQXUWyA3CqQUEuIJOmlEjKTBEiQAvpfDjCHjlV2Be4qTM6jamkJbiWtgnYPhJL6ONaGTiSPm7Byy57iaz/hbckldSOIoRhYBiMzeNoA0DiRZ9KmfSeXZ1rB8y8X5urSW+iBzf2SaOfzBvDpcoTuAaWx2DPazoOl28fP1hZ+kHUYvxbcMjttjauCFx+JII0dmuZNIwjfeG/GBb9frpSX219k1O4Wi6OEbHEr8at/XQ0y7gTikOxBn/s5wQIDAQAB\n"
		"-----END PUBLIC KEY-----",
		"LogID": "rDua7X+pZ0dXFZ5tfVdWcvnZgQCUHpve/+yhMTt1eC0=" },
		
		{ "Name" : "Venafi Gen2 CT log",
		"Key" : "-----BEGIN PUBLIC KEY-----\n"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjicnerZVCXTrbEuUhGW85BXx6lrYfA43zro/bAna5ymW00VQb94etBzSg4j/KS/Oqf/fNN51D8DMGA2ULvw3AQ==\n"
		"-----END PUBLIC KEY-----",
		"LogID": "AwGd8/2FppqOvR+sxtqbpz5Gl3T+d/V5/FoIuDKMHWs=" },
		
		{ "Name" : "CNNIC CT log",
		"Key" : "-----BEGIN PUBLIC KEY-----\n"
		"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv7UIYZopMgTTJWPp2IXhhuAf1l6a9zM7gBvntj5fLaFm9pVKhKYhVnno94XuXeN8EsDgiSIJIj66FpUGvai5samyetZhLocRuXhAiXXbDNyQ4KR51tVebtEq2zT0mT9liTtGwiksFQccyUsaVPhsHq9gJ2IKZdWauVA2Fm5x9h8B9xKn/L/2IaMpkIYtd967TNTP/dLPgixN1PLCLaypvurDGSVDsuWabA3FHKWL9z8wr7kBkbdpEhLlg2H+NAC+9nGKx+tQkuhZ/hWR65aX+CNUPy2OB9/u2rNPyDydb988LENXoUcMkQT0dU3aiYGkFAY0uZjD2vH97TM20xYtNQIDAQAB\n"
		"-----END PUBLIC KEY-----",
		"LogID": "pXesnO11SN2PAltnokEInfhuD0duwgPC7L7bGF8oJjg=" },
		
		{ "Name" : "StartCom log",
		"Key" : "-----BEGIN PUBLIC KEY-----\n"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESPNZ8/YFGNPbsu1Gfs/IEbVXsajWTOaft0oaFIZDqUiwy1o/PErK38SCFFWa+PeOQFXc9NKv6nV0+05/YIYuUQ==\n"
		"-----END PUBLIC KEY-----",
		"LogID": "NLtq1sPfnAPuqKSZ/3iRSGydXlysktAfe/0bzhnbSO8=" },
		
		{ "Name" : "Comodo 'Sabre' CT log",
		"Key" : "-----BEGIN PUBLIC KEY-----\n"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8m/SiQ8/xfiHHqtls9m7FyOMBg4JVZY9CgiixXGz0akvKD6DEL8S0ERmFe9U4ZiA0M4kbT5nmuk3I85Sk4bagA==\n"
		"-----END PUBLIC KEY-----",
		"LogID": "VYHUwhaQNgFK6gubVzxT8MDkOHhwJQgXL6OqHQcT0ww=" },
		
		{ "Name" : "Comodo 'Mammoth' CT log",
		"Key" : "-----BEGIN PUBLIC KEY-----\n"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7+R9dC4VFbbpuyOL+yy14ceAmEf7QGlo/EmtYU6DRzwat43f/3swtLr/L8ugFOOt1YU/RFmMjGCL17ixv66MZw==\n"
		"-----END PUBLIC KEY-----",
		"LogID": "b1N2rDHwMRnYmQCkURX/dxUcEdkCwQApBo2yCJo32RM=" },
		

    ]

if len( sys.argv ) <= 1:
    print( "Missing hostname argument." )
    print( "Usage: ./sct-verify hostname" )
    print( "" )
    print( "Example:" )
    print( "  ./sct-verify sni.velox.ch" )
    print( "" )
    print( "Known hosts implementing SCT TLS Extensions:" )
    print( " - blog.pierky.com" )
    print( " - sni.velox.ch" )
    print( " - ritter.vg" )
    quit()

HostName = sys.argv[1]

Args = [ OPENSSL_PATH ]
Args.extend( [ "s_client", "-serverinfo", "18", "-connect", "%s:443" % HostName, "-servername", HostName ])

OpenSSL= subprocess.Popen( Args, stdin=open('/dev/null', 'r'), stdout=subprocess.PIPE, stderr=subprocess.PIPE )
OpenSSL_stdout, OpenSSL_stderr = OpenSSL.communicate()
OpenSSL_exitcode = OpenSSL.wait()

if OpenSSL_exitcode != 0:
    print("OpenSSL can't connect to %s" % HostName)
    print(OpenSSL_stderr)
    quit()

ServerInfo18 = ""
ServerInfo18_Add = False
EECert = ""
EECert_Add = False
for L in OpenSSL_stdout.split('\n'):
    if L == "-----BEGIN SERVERINFO FOR EXTENSION 18-----":
        ServerInfo18_Add = True
    elif L == "-----END SERVERINFO FOR EXTENSION 18-----":
        ServerInfo18_Add = False
    elif L == "-----BEGIN CERTIFICATE-----":
        EECert_Add = True
    elif L == "-----END CERTIFICATE-----":
        EECert_Add = False
    elif ServerInfo18_Add:
        if ServerInfo18:
            ServerInfo18 = ServerInfo18 + '\n'
        ServerInfo18 = ServerInfo18 + L
    elif EECert_Add:
        if EECert:
            EECert = EECert + '\n'
        EECert = EECert + L

EECertDER = base64.b64decode( EECert )

Data = base64.b64decode( ServerInfo18 )
DataLen = len(Data)

if DataLen == 0:
    print("No TLS extensions found.")
    quit()

def ToHex( v ):
    if type(v) is int or type(v) is long:
        return hex(v)
    else:
        return ":".join("{:02x}".format(ord(c)) for c in v)

def Read( buf, offset, format ):
    Values = struct.unpack_from( format, buf, offset )
    NewOffset = offset + struct.calcsize( format )

    Ret = ()
    Ret = Ret + ( NewOffset, )
    Ret = Ret + Values
    return Ret

def ReadSCT( SCT ):
    print("===========================================================")
    Offset = 0

    Offset, SCTVersion = Read( SCT, Offset, "!B" )

    Offset, SCTLogID = Read( SCT, Offset, "!32s" )
    Base64LogID = base64.b64encode( SCTLogID )

    Offset, SCTTimestamp = Read( SCT, Offset, "!Q" )

    Offset, SCTExtensionsLen = Read( SCT, Offset, "!H" )

    #FIXME
    if SCTExtensionsLen > 0:
        print("Extensions length > 0; not implemented")
        return

    Offset, SCTSignatureAlgHash = Read( SCT, Offset, "!B" )
    Offset, SCTSignatureAlgSign = Read( SCT, Offset, "!B" )

    Offset, SCTSignatureLen = Read( SCT, Offset, "!H" )
    Offset, SCTSignature = Read( SCT, Offset, "!%ss" % SCTSignatureLen )

    # print SCT information

    print( "Version   : %s" % ToHex( SCTVersion ) )
    SCTLogID1, SCTLogID2 = struct.unpack( "!16s16s", SCTLogID )
    print( "LogID     : %s" % ToHex( SCTLogID1 ) )
    print( "            %s" % ToHex( SCTLogID2 ) )
    print( "LogID b64 : %s" % Base64LogID )
    print( "Timestamp : %s (%s)" % ( SCTTimestamp, ToHex( SCTTimestamp ) ) )
    print( "Extensions: %s (%s)" % ( SCTExtensionsLen, ToHex( SCTExtensionsLen )) )
    print( "Algorithms: %s/%s (hash/sign)" % ( ToHex( SCTSignatureAlgHash ), ToHex ( SCTSignatureAlgSign ) )) 

    SigOffset = 0
    while SigOffset < len( SCTSignature ):
        if len( SCTSignature ) - SigOffset > 16:
            SigBytesToRead = 16
        else:
            SigBytesToRead = len( SCTSignature ) - SigOffset
        SigBytes = struct.unpack_from( "!%ss" % SigBytesToRead, SCTSignature, SigOffset )[0]

        if SigOffset == 0:
            print( "Signature : %s" % ToHex( SigBytes ) )
        else:
            print( "            %s" % ToHex( SigBytes ) )
    
        SigOffset = SigOffset + SigBytesToRead

    # look for signing log and its key

    PubKey = None
    for Log in LOGS:
        if Log["LogID"] == Base64LogID:
            print( "Log found : %s" % Log["Name"])
            PubKey = Log["Key"]

    if not PubKey:
        print("Log not found")
        return

    # signed data

    # 1 version
    # 1 signature_type
    # 8 timestamp
    # 2 entry_type
    # 3 DER lenght
    # x DER
    # 2 extensions length

    EECertDERLen = len( EECertDER )
    _, EECertDERLen1, EECertDERLen2, EECertDERLen3 = struct.unpack( "!4B", struct.pack( "!I", EECertDERLen ) )
    
    Data = struct.pack("!BBQhBBB%ssh" % len( EECertDER ), SCTVersion, 0, SCTTimestamp, 0, EECertDERLen1, EECertDERLen2, EECertDERLen3, EECertDER, SCTExtensionsLen )

    File = open("tmp-signeddata.bin", "wb")
    File.write( Data )
    File.close()

    File = open("tmp-pubkey.pem", "w")
    File.write( PubKey )
    File.close()

    File = open("tmp-signature.bin", "wb")
    File.write( SCTSignature )
    File.close()

    Args = [ OPENSSL_PATH ] 
    Args.extend( [ "dgst", "-sha256", "-verify", "tmp-pubkey.pem", "-signature", "tmp-signature.bin", "tmp-signeddata.bin" ] )

    OpenSSL= subprocess.Popen( Args, stdin=open('/dev/null', 'r'), stdout=subprocess.PIPE, stderr=subprocess.PIPE )
    OpenSSL_stdout, OpenSSL_stderr = OpenSSL.communicate()
    OpenSSL_exitcode = OpenSSL.wait()

    if OpenSSL_exitcode == 0:
        print( "Result    : %s" % OpenSSL_stdout )
    else:
        print( "OpenSSL error - Exit code %d" % OpenSSL_exitcode )
        print( OpenSSL_stderr )

Offset = 0
Offset, TLS_ExtensionType, TLS_ExtensionLen = Read( Data, Offset, "!HH" )
Offset, SignedCertificateTimestampListLen = Read( Data, Offset, "!H" )

while Offset < DataLen:
    Offset, SCTLen = Read( Data, Offset, "!H" )
    Offset, SCT = Read( Data, Offset, "!%ss" % SCTLen )
    ReadSCT( SCT )
