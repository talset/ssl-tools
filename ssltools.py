#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Florian Lambert <flambert@redhat.com>
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#
# Requirments: python build-essential libssl-dev libffi-dev python-dev
#

import sys
import argparse
import subprocess
import time
from datetime import datetime

import os
from OpenSSL import crypto

TYPE_RSA = crypto.TYPE_RSA


VERSION = '1.0'

PARSER = argparse.ArgumentParser(description='Openssl tools')

PARSER.add_argument("-gen","--gencert", action='store_true',
                    help='Generate a new certificat')
PARSER.add_argument("-s", "--subject", type=str,
                    help='Subject countryName, localityName, organizationalUnitName (Default : C=FR/L=Paris/O=redhat/OU=rcip)',
                    default="C=FR/L=Paris/O=redhat/OU=rcip")
PARSER.add_argument("-cn", "--common-name", type=str,
                    help='CommonName (Default : *.rcip.redhat.com)',
                    default="*.rcip.redhat.com")
PARSER.add_argument("-ip", "--sanip", type=str,
                    help='Subject Alternative Name IP ex: 127.0.0.1,10.100.0.1')
PARSER.add_argument("-dns", "--sandns", type=str,
                    help='Subject Alternative Name DNS ex: localhost,example.com')
PARSER.add_argument("-d", "--days", type=int,
                    help='specifies the number of days to make a certificate valid for. (Default : 3650)',
                    default=3650)
PARSER.add_argument("-b", "--bits", type=int,
                    help='Key size (Default : 4096)',
                    default=4096)

PARSER.add_argument("-va", "--verify-auto", type=str,
                    help='Determine if it is a key or cert and run the good verify')
PARSER.add_argument("-vk", "--verify-key", type=str,
                    help='Print the details of a key')
PARSER.add_argument("-vc", "--verify-certificate", type=str,
                    help='Print the details of a cert')

PARSER.add_argument("-v", "--version", action='store_true',
                    help='Print script version')
ARGS = PARSER.parse_args()


class Ssltools(object):
    """
    A little toolbox to manage certs
    """

    def __init__(self):
        pass

################################
#
#         Cert part
#
################################

    def gen_cert(self,
                 subject=None,
                 cn=None,
                 days=None,
                 bits=None,
                 sandns=None,
                 sanip=None,
                 rootcert_name="ca.crt",
                 rootkey_name="ca.key",
                 cn_rootcert="Certificate Authority",
                 cert_name="server.crt",
                 key_name="server.key",
                 srl_file="file.srl",
                 certs_path="./certs"):

        self.subject = subject
        self.cn = cn
        self.days = days
        self.bits = bits
        self.sanip = sanip
        self.sandns = sandns
        self.rootcert_name = rootcert_name
        self.rootkey_name = rootkey_name
        self.cn_rootcert = cn_rootcert
        self.cert_name = cert_name
        self.key_name = key_name
        self.srl_file = srl_file
        self.certs_path = certs_path

        #root CA and key
        (rootCA, rootKEY)=self._create_rootcert()


        #root CA and key
        self._create_sign_cert(rootCA, rootKEY)


    def _create_rootcert(self):
        #create certs directory
        print "[Create rootCert/Key]" 
        if not os.path.exists(self.certs_path):
                os.makedirs(self.certs_path)

        print "  [Create %s]" % self.rootkey_name
        if not os.path.exists("%s/%s" % (self.certs_path, self.rootkey_name)):
                pkey=self.create_pkey(certs_path=self.certs_path, pkey_name=self.rootkey_name)
        else:
                print "    %s/%s Already exist [Keep the existing]" % (self.certs_path, self.rootkey_name)
                existing_pkey=open("%s/%s" % (self.certs_path, self.rootkey_name), 'r').read()
                pkey=crypto.load_privatekey(crypto.FILETYPE_PEM, existing_pkey)


        print "  [Create req]"
        subject=dict(item.split("=") for item in self.subject.split("/"))
        req=self.create_req(pkey, **subject)


        print "  [Create %s]" % self.rootcert_name

        if not os.path.exists("%s/%s" % (self.certs_path, self.rootcert_name)):
                #write srl file with 0 (first cert)
                print "    write serial 0 in %s/%s" % (self.certs_path, self.srl_file)
                self.write_serial(self.certs_path, self.srl_file, 0)
                #Create cert with request
                cert=self.create_cert(req, (req, pkey), 0, (0, 60*60*24*int(self.days)),certs_path=self.certs_path,cert_name=self.rootcert_name)
        else:
                print "    %s/%s Already exist [Keep the existing]" % (self.certs_path, self.rootcert_name)
                existing_cert=open("%s/%s" % (self.certs_path, self.rootcert_name), 'r').read()
                cert=crypto.load_certificate(crypto.FILETYPE_PEM, existing_cert)

        return (cert, pkey)

    def _create_sign_cert(self,rootCA, rootKEY):
        #create certs directory
        print "[Create serverCert/Key]" 
        if not os.path.exists(self.certs_path):
                os.makedirs(self.certs_path)

        print "  [Get new Serial]"
        #get the last and +1
        serial=(int(self.get_serial(self.certs_path, self.srl_file))+1)
        print "    New serial is %s" % serial
        print "  [Write the new Serial]"
        self.write_serial(self.certs_path, self.srl_file, serial)

        cert_name="%s_%s" % (serial, self.cert_name)
        key_name="%s_%s" % (serial, self.key_name)

        print "  [Create %s]" % key_name
        if not os.path.exists("%s/%s" % (self.certs_path, key_name)):
                pkey=self.create_pkey(certs_path=self.certs_path, pkey_name=key_name)
        else:
                print "    %s/%s Already exist [Fail]" % (self.certs_path, key_name)
                sys.exit(1)


        print "  [Create req]"
        subject=dict(item.split("=") for item in self.subject.split("/"))
        subject.update({'CN': self.cn})
        #TODO Add CN and SAN
        req=self.create_req(pkey, **subject)


        print "  [Create %s]" % cert_name

        if not os.path.exists("%s/%s" % (self.certs_path, cert_name)):
                #Create cert with request
                cert=self.create_cert(req, (rootCA, rootKEY), serial, (0, 60*60*24*int(self.days)),certs_path=self.certs_path,cert_name=cert_name)
        else:
                print "    %s/%s Already exist [Fail]" % (self.certs_path, cert_name)
                sys.exit(1)

        chain_cert="%s_chain_%s" % (serial, self.cert_name)
        print "  [Create Chain %s]" % chain_cert
        #get the txt version to write the chain cert
        txt_key=crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey)
        txt_cert=crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
        txt_cacert=crypto.dump_certificate(crypto.FILETYPE_PEM, rootCA)
        open("%s/%s" % (self.certs_path, chain_cert), 'w').write("%s\n%s\n%s" % (txt_cert,txt_key,txt_cacert))


    def create_pkey(self,certs_path,pkey_name):
        """
        Create private key.
        Arguments: certs_path - Certificats directory
                   pkey_name - Name for the private key
        Returns:   The private key generated
        """
        pkey = crypto.PKey()
        pkey.generate_key(TYPE_RSA, self.bits)
        open("%s/%s" % (certs_path, pkey_name), 'w').write(crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey))
        return pkey

    def create_req(self, pkey, digest="md5", **subject):
        """
        Create a certificate request.
        Arguments: pkey   - The key to associate with the request
                   digest - Digestion method to use for signing, default is md5
                   **subject - The name of the subject of the request, possible
                            arguments are:
                              C     - Country subject
                              ST    - State or province subject
                              L     - Locality subject
                              O     - Organization subject
                              OU    - Organizational unit subject
                              CN    - Common subject
                              emailAddress - E-mail address
        Returns:   The certificate request in an X509Req object
        """

        req = crypto.X509Req()
        subj = req.get_subject()

        for (key,value) in subject.items():
                    setattr(subj, key, value)

        #TODO san
        extention=crypto.X509Extension(type_name="subjectAltName", critical=False, value="IP:192.168.7.1")
        req.add_extensions([extention])

        req.set_pubkey(pkey)
        req.sign(pkey, digest)
        return req

    #cacert = createCertificate(careq, (careq, cakey), 0, (0, 60*60*24*365*5)) # five years
    #cert = createCertificate(req, (cacert, cakey), 1, (0, 60*60*24*365*5)) # five years
    def create_cert(self, req, (issuerCert, issuerKey), serial, (notBefore, notAfter), certs_path,cert_name, digest="md5"):
        """
        Generate a certificate given a certificate request.
        Arguments: req        - Certificate reqeust to use
                   issuerCert - The certificate of the issuer
                   issuerKey  - The private key of the issuer
                   serial     - Serial number for the certificate
                   notBefore  - Timestamp (relative to now) when the certificate
                                starts being valid
                   notAfter   - Timestamp (relative to now) when the certificate
                                stops being valid
                   digest     - Digest method to use for signing, default is md5
        Returns:   The signed certificate in an X509 object
        """

        cert = crypto.X509()
        cert.set_serial_number(serial)
        cert.gmtime_adj_notBefore(notBefore)
        cert.gmtime_adj_notAfter(notAfter)
        cert.set_issuer(issuerCert.get_subject())
        cert.set_subject(req.get_subject())
        cert.set_pubkey(req.get_pubkey())
        cert.sign(issuerKey, digest)

        open("%s/%s" % (certs_path, cert_name), 'w').write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

        return cert

    def get_serial(self, certs_path, srl_file):
        if not os.path.exists("%s/%s" % (certs_path, srl_file)):
                print "    %s/%s Not exist. [Creating file ...]" % (certs_path, srl_file)
                self.write_serial(certs_path, srl_file, 0)
                return 0

        return int(open("%s/%s" % (certs_path, srl_file), 'r').read())

    def write_serial(self, certs_path, srl_file, serial):
        open("%s/%s" % (certs_path, srl_file), 'w').write(str(serial))


################################
#
#         Verify part
#
################################

    def verify_key(self, pkey_path):
        print pkey_path
        existing_pkey=open("%s" % (pkey_path), 'r').read()
        pkey=crypto.load_privatekey(crypto.FILETYPE_PEM, existing_pkey)

        #print "%s\n" % existing_pkey
        if pkey.type() == 6:
                ktype='RSA'
        elif pkey.type() == 116:
                ktype='DSA'
        else:
                ktype='Unknow'

        print "Type: %s" % ktype
        print "Bits: %s" % pkey.bits()
        print "Consistency: %s" % pkey.check()

    def verify_certificate(self, cert_path):
        print cert_path
        existing_cert=open("%s" % (cert_path), 'r').read()
        cert=crypto.load_certificate(crypto.FILETYPE_PEM, existing_cert)

        print "Digest md5: %s" % cert.digest('md5')
        for i in range(0,cert.get_extension_count()) :
            print "Extention: %s" % cert.get_extension(i)

        print "Issuer: %s" % ('/'.join(['%s=%s' % (k, v) for k, v in cert.get_issuer().get_components()]))

        valid_notAfter=datetime.fromtimestamp(time.mktime(time.strptime(cert.get_notAfter(), "%Y%m%d%H%M%SZ")))
        valid_notBefore=datetime.fromtimestamp(time.mktime(time.strptime(cert.get_notBefore(), "%Y%m%d%H%M%SZ")))
        print "Certificate starts being valid: %s" % valid_notBefore.strftime("%Y-%m-%d %Hh%Mm%S")
        print "Certificate stops being valid: %s" % valid_notAfter.strftime("%Y-%m-%d %Hh%Mm%S")
        print "Expired: %s" % cert.has_expired()

        #pub key type
        pubkey=cert.get_pubkey()
        if pubkey.type() == 6:
                pubktype='RSA'
        elif pubkey.type() == 116:
                pubktype='DSA'
        else:
                ktype='Unknow'
        print "Pub key Type: %s" % pubktype
        print "Pub key bits: %s" % pubkey.bits()

        print "Serial number: %s" % cert.get_serial_number()
        print "Signature algorithm: %s" % cert.get_signature_algorithm()
        print "Subject: %s" % ('/'.join(['%s=%s' % (k, v) for k, v in cert.get_subject().get_components()]))
        print "Version: %s" % cert.get_version()

    def verify_auto(self, path_file):

        file=open("%s" % (path_file), 'r').read()
        if file.startswith('-----BEGIN CERTIFICATE'):
                self.verify_certificate(path_file)
        elif file.startswith('-----BEGIN PRIVATE'):
                self.verify_key(path_file)
        else:
                print "Can't find the type of %s" % path_file


   # def _auth(self):
   #     cmd = ("oc login %s:%s -u%s -p%s --insecure-skip-tls-verify=True 2>&1 > /dev/null"
   #            % (self.host, self.port, self.username, self.password))
   #     subprocess.check_output(cmd, shell=True)

   #     cmd = "oc whoami -t"
   #     stdout = subprocess.check_output(cmd, shell=True)

   #     return stdout.strip()



if __name__ == "__main__":

    if ARGS.version:
        print "version: %s" % (VERSION)
        sys.exit(0)

    tools = Ssltools()

    if ARGS.verify_auto:
        tools.verify_auto(ARGS.verify_auto)

    if ARGS.verify_key:
        tools.verify_key(ARGS.verify_key)

    if ARGS.verify_certificate:
        tools.verify_certificate(ARGS.verify_certificate)

    if ARGS.gencert:
        tools.gen_cert(subject=ARGS.subject,
                     cn=ARGS.common_name,
                     days=ARGS.days,
                     sandns=ARGS.sandns,
                     bits=ARGS.bits,
                     sanip=ARGS.sanip)
