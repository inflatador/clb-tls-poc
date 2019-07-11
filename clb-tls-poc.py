#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# clbs-tls-poc.py
# given a region, Cloud Load Balancer ID, and TLS version:
# - prints current ciphers and TLS versions allowed
# - disables TLS version provided
# version: 0.0.1a
# Copyright 2019 Brian King
# License: Apache

import argparse
from datetime import tzinfo, timedelta, datetime, date
from getpass import getpass
import json
import keyring
import os
import plac

import requests
import sys
import time
# from time import time

def find_endpoints(auth_token, headers, region, desired_service="cloudLoadBalancers"):

    url = ("https://identity.api.rackspacecloud.com/v2.0/tokens/%s/endpoints" % auth_token)
    #region is always uppercase in the service catalog
    region = region.upper()
    raw_service_catalog = requests.get(url, headers=headers)
    raw_service_catalog.raise_for_status()
    the_service_catalog = raw_service_catalog.json()
    endpoints = the_service_catalog["endpoints"]

    for service in endpoints:
        if desired_service == service["name"] and region == service["region"]:
            desired_endpoint = service["publicURL"]

    return desired_endpoint

def getset_keyring_credentials(username=None, password=None):
    #Method to retrieve credentials from keyring.
    print (sys.version_info.major)
    username = keyring.get_password("raxcloud", "username")
    if username is None:
        if sys.version_info.major < 3:
            username = raw_input("Enter Rackspace Username: ")
            keyring.set_password("raxcloud", 'username', username)
            print ("Username value saved in keychain as raxcloud username.")
        elif sys.version_info.major >= 3:
            username = input("Enter Rackspace Username: ")
            keyring.set_password("raxcloud", 'username', username)
            print ("Username value saved in keychain as raxcloud username.")
    else:
        print ("Authenticating to Rackspace cloud as %s" % username)
    password = keyring.get_password("raxcloud", "password")
    if password is None:
        password = getpass("Enter Rackspace API key:")
        keyring.set_password("raxcloud", 'password' , password)
        print ("API key value saved in keychain as raxcloud password.")
    return username, password

def wipe_keyring_credentials(username, password):
    """Wipe credentials from keyring."""
    try:
        keyring.delete_password('raxcloud', 'username')
        keyring.delete_password('raxcloud', 'password')
    except:
        pass

    return True

# Request to authenticate using password
def get_auth_token(username,password):
    #setting up api call
    url = "https://identity.api.rackspacecloud.com/v2.0/tokens"
    headers = {'Content-type': 'application/json'}
    payload = {'auth':{'passwordCredentials':{'username': username,'password': password}}}
    payload2 = {'auth':{'RAX-KSKEY:apiKeyCredentials':{'username': username,'apiKey': password}}}

    #authenticating against the identity
    try:
        r = requests.post(url, headers=headers, json=payload)
    except requests.ConnectionError as e:
        print("Connection Error: Check your interwebs!")
        sys.exit()


    if r.status_code != 200:
        r = requests.post(url, headers=headers, json=payload2)
        if r.status_code != 200:
            print ("Error! API responds with %d" % r.status_code)
            print("Rerun the script and you will be prompted to re-enter username/password.")
            wipe_keyring_credentials(username, password)
            sys.exit()
        else:
            print("Authentication was successful!")
    elif r.status_code == 200:
        print("Authentication was successful!")

    #loads json reponse into data as a dictionary.
    data = r.json()
    #assign token and account variables with info from json response.
    auth_token = data["access"]["token"]["id"]

    headers = ({'content-type': 'application/json', 'Accept': 'application/json',
    'X-Auth-Token': auth_token})

    return auth_token, headers

def show_tls_and_cipher_vers(clb_endpoint, headers, clb_id):
    clb_url = "{}/loadbalancers/{}/ssltermination".format(clb_endpoint, clb_id)
    current_clb_config = requests.get(url=clb_url, headers=headers)
    print ("Here's the keys: {}".format(current_clb_config.json()["sslTermination"].keys()))
    security_protocols = current_clb_config.json()["sslTermination"]["securityProtocols"]
    for security_protocol in security_protocols:
        if security_protocol["securityProtocolStatus"] == "ENABLED":
            print ("TLS version {} is enabled.".format(security_protocol["securityProtocolName"]))
    return clb_url
#
def disable_tls_vers(clb_url, headers, tls_vers):
    payload = {
                  "sslTermination": {
                    "securityProtocols": [
                      {
                        "securityProtocolName": "TLS_10",
                        "securityProtocolStatus": "DISABLED"
                      },
                      {
                        "securityProtocolName": "TLS_11",
                        "securityProtocolStatus": "DISABLED"
                      }
                    ]
                  }
                }
    disable_tls = requests.put(url=clb_url, headers=headers, json=payload)
    print (disable_tls.json())



#begin main function
@plac.annotations(
    region = plac.Annotation("Rackspace Cloud region"),
    clb_id = plac.Annotation("Cloud Load Balancer ID"),
    tls_vers = plac.Annotation("TLS version to disable",'positional',
               None, str, ["1.0", "1.1"], None)
                )

def main(region, clb_id, tls_vers):
    username, password = getset_keyring_credentials()

    auth_token, headers = get_auth_token(username, password)

    clb_endpoint = find_endpoints(auth_token, headers, region,
                  desired_service="cloudLoadBalancers")

    # print (clb_endpoint)

    clb_url = show_tls_and_cipher_vers(clb_endpoint, headers, clb_id)

    disable_tls_vers(clb_url, headers, tls_vers)

if __name__ == '__main__':
    import plac
    plac.call(main)
