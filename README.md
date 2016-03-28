# ssl-tools
Scripts to simplify the management of certificates


## ssltools.py

###Dependancy packages

```bash
python build-essential libssl-dev libffi-dev python-dev
```

###Installation

```bash
sudo pip install pyopenssl --upgrade
```
Script tested with pyOpenSSL==16.0.0

###Help

```bash
python ssltools.py -h
usage: ssltools.py [-h] [-gen] [-s SUBJECT] [-cn COMMON_NAME]
                   [-ip SANIP [SANIP ...]] [-dns SANDNS [SANDNS ...]]
                   [-d DAYS] [-b BITS] [-va VERIFY_AUTO] [-vk VERIFY_KEY]
                   [-vc VERIFY_CERTIFICATE] [-v]

Openssl tools

optional arguments:
  -h, --help            show this help message and exit
  -gen, --gencert       Generate a new certificat
  -s SUBJECT, --subject SUBJECT
                        Subject countryName, localityName,
                        organizationalUnitName (Default :
                        C=FR/L=Paris/O=redhat/OU=rcip)
  -cn COMMON_NAME, --common-name COMMON_NAME
                        CommonName (Default : *.rcip.redhat.com)
  -ip SANIP [SANIP ...], --sanip SANIP [SANIP ...]
                        Subject Alternative Name IP ex: 127.0.0.1 10.100.0.1
  -dns SANDNS [SANDNS ...], --sandns SANDNS [SANDNS ...]
                        Subject Alternative Name DNS ex: localhost example.com
                        example2.com
  -d DAYS, --days DAYS  specifies the number of days to make a certificate
                        valid for. (Default : 3650)
  -b BITS, --bits BITS  Key size (Default : 4096)
  -va VERIFY_AUTO, --verify-auto VERIFY_AUTO
                        Determine if it is a key or cert and run the good
                        verify
  -vk VERIFY_KEY, --verify-key VERIFY_KEY
                        Print the details of a key
  -vc VERIFY_CERTIFICATE, --verify-certificate VERIFY_CERTIFICATE
                        Print the details of a cert
  -v, --version         Print script version
```

###Examples

Generate a CA and Server cert with cn and SAN (dns and ips)

```bash
python ssltools.py -gen -cn *.foo.com -dns foo.bar.com foo.bla.com -ip 127.0.0.1 10.1.0.1
```

Create a second Server cert signed by the previous CA (by default it use the same certs/ca.crt)
```bash
python ssltools.py -gen -cn *.fii.com -dns fii.bar.com fii.bla.com -ip 127.0.0.1 10.1.0.1
```

Display details of the server key
```bash
python ssltools.py -vk certs/1_server.key 
certs/1_server.key
Type: RSA
Bits: 4096
Consistency: True
```

Display details of the server cert
```bash
python ssltools.py -vc certs/1_server.crt 
certs/1_server.crt
Subject: C=FR/OU=rcip/CN=*.foo.com/O=redhat/L=Paris
Extention: DNS:foo.bar.com, DNS:foo.bla.com, IP Address:127.0.0.1, IP Address:10.1.0.1
Issuer: C=FR/L=Paris/O=redhat/OU=rcip
Certificate starts being valid: 2016-03-28 08h50m35
Certificate stops being valid: 2026-03-26 08h50m35
Expired: False
Digest md5: 4C:F3:E4:15:C2:6C:C6:9A:57:91:FA:F9:59:7E:2A:4E
Signature algorithm: md5WithRSAEncryption
Pub key Type: RSA
Pub key bits: 4096
Serial number: 1
Version: 0
```

You can also use --verify-auto it will read the begining of the file to determine if it is key or cert

```bash
python ssltools.py -va certs/1_server.key
python ssltools.py -va certs/1_server.crt
```
