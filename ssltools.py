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
# Requirments: python
#

import sys
import argparse
import subprocess

import os
from OpenSSL import crypto

TYPE_RSA = crypto.TYPE_RSA


VERSION = '1.0'

PARSER = argparse.ArgumentParser(description='Openssl tools')

PARSER.add_argument("-gen","--gencert", action='store_true',
                    help='Generate a new certificat')
PARSER.add_argument("-s", "--subject", type=str,
                    help='Subject countryName, localityName, organizationalUnitName (Default : /C=FR/L=Paris/O=redhat/OU=rcip)',
                    default="/C=FR/L=Paris/O=redhat/OU=rcip")
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

PARSER.add_argument("-vk", "--verify-key", type=str,
                    help='Print the contenant of a key')

PARSER.add_argument("-v", "--version", action='store_true',
                    help='Print script version')
ARGS = PARSER.parse_args()


class Ssltools(object):
    """
    A little toolbox to manage certs
    """

    def __init__(self):
        pass


    def gen_cert(self,
                 subject=None,
                 cn=None,
                 days=None,
                 bits=None,
                 sandns=None,
                 sanip=None,
                 rootcert_name="ca.crt",
                 rootkey_name="ca.key",
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
        self.cert_name = rootcert_name
        self.key_name = rootkey_name
        self.srl_file = srl_file
        self.certs_path = certs_path

        print "%s" % self.cn

        self._create_rootcert()
        #create_rootcert()
        #root CA and key
        #openssl genrsa -out ca.key 4096
        #openssl req -days 3650 -out ca.pem -new -x509 -subj /C=FR/L=Paris/O=redhat/OU=redhat

        #create_req_cert()
        #openssl genrsa -out test.key 2048
        #openssl req -days 3650 -key test.key -new -out test.req -subj /C=FR/L=Paris/O=redhat/OU=redhat/CN=*.mydomain.com

        #update_srl
        #echo '00' > file.srl

        #create_cert
        #openssl x509 -req -days 3650 -in test.req -CA ca.pem -CAkey privkey.pem -CAserial file.srl -out test.pem

        #gen_chain_cert
        #cat test.pem test.key ca.pem > chain_test.pem

    def _create_rootcert(self):

        #create certs directory
        
        if not os.path.exists(self.certs_path):
                os.makedirs(self.certs_path)

        pkey = crypto.PKey()
        pkey.generate_key(TYPE_RSA, self.bits)
        open("certs/%s" % self.rootkey_name, 'w').write(crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey))
        print pkey

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

    #if not ARGS.token:
    #    PARSER.print_help()
    #    sys.exit(STATE_UNKNOWN)

    tools = Ssltools()

#    ARGS.verify_key


    if ARGS.gencert:
        tools.gen_cert(subject=ARGS.subject,
                     cn=ARGS.common_name,
                     days=ARGS.days,
                     sandns=ARGS.sandns,
                     bits=ARGS.bits,
                     sanip=ARGS.sanip)
