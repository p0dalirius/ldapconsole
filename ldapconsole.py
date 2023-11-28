#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : ldapsearch.py
# Author             : Podalirius (@podalirius_)
# Date created       : 29 Jul 2021

import readline
import argparse
import sys
import traceback
import logging
from sectools.windows.ldap import raw_ldap_query, init_ldap_session
from sectools.windows.crypto import nt_hash, parse_lm_nt_hashes
from ldap3.protocol.formatters.formatters import format_sid
import re
import os
import ssl
import binascii


class CommandCompleter(object):
    def __init__(self):
        self.options = {
            "diff": [],
            "query": [],
            "presetquery": ["get_all_users", "get_all_groups", "get_all_kerberoastables", "get_all_descriptions"],
            "help": [],
            "infos": [],
            "exit": []
        }

    def complete(self, text, state):
        if state == 0:
            if len(text) == 0:
                self.matches = [s for s in self.options.keys()]
            elif len(text) != 0:

                if text.count(' ') == 0:
                    self.matches = [s for s in self.options.keys() if s and s.startswith(text)]
                elif text.count(' ') == 1:
                    command, remainder = text.split(' ', 1)
                    if command in self.options.keys():
                        self.matches = [command + " " + s for s in self.options[command] if s and s.startswith(remainder)]
                    else:
                        pass
                else:
                    self.matches = []
            else:
                self.matches = self.options.keys()[:]
        try:
            return self.matches[state] + " "
        except IndexError:
            return None


readline.set_completer(CommandCompleter().complete)
readline.parse_and_bind('tab: complete')
readline.set_completer_delims('\n')


### Data utils

def dict_get_paths(d):
    paths = []
    for key in d.keys():
        if type(d[key]) == dict:
            paths = [[key] + p for p in dict_get_paths(d[key])]
        else:
            paths.append([key])
    return paths


def dict_path_access(d, path):
    for key in path:
        if key in d.keys():
            d = d[key]
        else:
            return None
    return d


### LDAPConsole

class LDAPConsole(object):
    """docstring for LDAPConsole."""

    def __init__(self, ldap_server, ldap_session, target_dn, debug=False):
        super(LDAPConsole, self).__init__()
        self.ldap_server = ldap_server
        self.ldap_session = ldap_session
        self.delegate_from = None
        self.target_dn = target_dn
        self.debug = debug

        # if self.debug == True:
        #    logging.info("Using dn: %s" % self.target_dn)

    def query(self, query, attributes=['*'], quiet=False):
        results = {}
        try:
            # https://ldap3.readthedocs.io/en/latest/searches.html#the-search-operation
            paged_response = True
            paged_cookie = None
            while paged_response == True:
                self.ldap_session.search(
                    self.target_dn, query, attributes=attributes,
                    size_limit=0, paged_size=1000, paged_cookie=paged_cookie
                )
                if "controls" in self.ldap_session.result.keys():
                    if "1.2.840.113556.1.4.319" in self.ldap_session.result["controls"].keys():
                        _tmp_cookie = self.ldap_session.result["controls"]["1.2.840.113556.1.4.319"]["value"]["cookie"]
                        if len(_tmp_cookie) == 0:
                            paged_response = False
                        else:
                            paged_response = True
                            paged_cookie = _tmp_cookie
                    else:
                        paged_response = False
                else:
                    paged_response = False
                #
                for entry in self.ldap_session.response:
                    if entry['type'] != 'searchResEntry':
                        continue
                    results[entry['dn']] = entry["raw_attributes"]
                    if quiet == False:
                        self._print_entry_colored(entry['dn'], results[entry['dn']])
        except ldap3.core.exceptions.LDAPInvalidFilterError as e:
            print("Invalid Filter. (ldap3.core.exceptions.LDAPInvalidFilterError)")
        except Exception as e:
            raise e
        return results

    def oldquery(self, query, attributes=['*'], quiet=False):
        results = {}
        try:
            self.ldap_session.search(self.target_dn, query, attributes=attributes)
            for entry in self.ldap_session.response:
                if entry['type'] != 'searchResEntry':
                    continue
                results[entry['dn']] = entry["raw_attributes"]
                if quiet == False:
                    self._print_entry_colored(entry['dn'], results[entry['dn']])
        except ldap3.core.exceptions.LDAPInvalidFilterError as e:
            print("\x1b[91mInvalid Filter.\x1b[0m")
        except Exception as e:
            if self.debug == True:
                traceback.print_exc()
            logging.error(str(e))
        return results

    def _print_entry_colored(self, dn, entry):
        def _parse_print(element, depth=0, maxdepth=15, prompt=['  | ', '  └─>']):
            _pre = prompt[0] * (depth) + prompt[1]
            if depth < maxdepth:
                if type(element) == ldap3.utils.ciDict.CaseInsensitiveDict:
                    element = {key: value for key, value in element.items()}
                if type(element) == dict:
                    for key in element.keys():
                        if type(element[key]) == dict:
                            _parse_print(element[key], depth=(depth + 1), maxdepth=maxdepth, prompt=prompt)
                        #
                        elif type(element[key]) == ldap3.utils.ciDict.CaseInsensitiveDict:
                            _ldap_ciDict = {key: value for key, value in element[key].items()}
                            _parse_print(_ldap_ciDict, depth=(depth + 1), maxdepth=maxdepth, prompt=prompt)
                        #
                        elif type(element[key]) == list:
                            if len(element[key]) == 0:
                                print(_pre + "\"\x1b[92m%s\x1b[0m\": []" % str(key))
                            elif len(element[key]) == 1:
                                print(_pre + "\"\x1b[92m%s\x1b[0m\": [\x1b[96m%s\x1b[0m]" % (str(key), element[key][0]))
                            else:
                                print(_pre + "\"\x1b[92m%s\x1b[0m\": %s" % (str(key), "["))
                                for _list_element in element[key]:
                                    _parse_print(_list_element, depth=(depth + 1), maxdepth=maxdepth, prompt=prompt)
                                print(_pre + "%s" % "],")
                        #
                        elif type(element[key]) == str:
                            print(_pre + "\"\x1b[92m%s\x1b[0m\": \"\x1b[96m%s\x1b[0m\"," % (str(key), str(element[key])))
                        #
                        else:
                            print(prompt[0] * (depth) + prompt[1] + "\"\x1b[92m%s\x1b[0m\": \x1b[96m%s\x1b[0m," % (str(key), str(element[key])))
                else:
                    print(prompt[0] * (depth) + prompt[1] + "\x1b[96m%s\x1b[0m" % str(element))
            else:
                # Max depth reached
                pass

        #
        print("[>] %s" % dn)
        _parse_print(entry, prompt=['    ', '    '])


def print_help():
    print(" - %-15s %s " % ("base", "Sets LDAP base DN."))
    print(" - %-15s %s " % ("diff", "Show the differences between the last two requests."))
    print(" - %-15s %s " % ("query", "Sends a query to LDAP."))
    print(" - %-15s %s " % ("presetquery", "Use a builtin preset query."))
    print(" - %-15s %s " % ("help", "Displays this help message."))
    print(" - %-15s %s " % ("exit", "Exits the script."))
    return


def parse_args():
    parser = argparse.ArgumentParser(add_help=True, description='Python (re)setter for property msDS-KeyCredentialLink for Shadow Credentials attacks.')
    parser.add_argument('--use-ldaps', action='store_true', help='Use LDAPS instead of LDAP')
    parser.add_argument("-q", "--quiet", dest="quiet", action="store_true", default=False, help="show no information at all")
    parser.add_argument("-debug", dest="debug", action="store_true", default=False, help="Debug mode")

    authconn = parser.add_argument_group('authentication & connection')
    authconn.add_argument('--dc-ip', action='store', metavar="ip address", help='IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted it will use the domain part (FQDN) specified in the identity parameter')
    authconn.add_argument('--kdcHost', dest="kdcHost", action='store', metavar="FQDN KDC", help='FQDN of KDC for Kerberos.')
    authconn.add_argument("-d", "--domain", dest="auth_domain", metavar="DOMAIN", action="store", help="(FQDN) domain to authenticate to")
    authconn.add_argument("-u", "--user", dest="auth_username", metavar="USER", action="store", help="user to authenticate with")

    secret = parser.add_argument_group()
    cred = secret.add_mutually_exclusive_group()
    cred.add_argument('--no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    cred.add_argument("-p", "--password", dest="auth_password", metavar="PASSWORD", action="store", help="password to authenticate with")
    cred.add_argument("-H", "--hashes", dest="auth_hashes", action="store", metavar="[LMHASH:]NTHASH", help='NT/LM hashes, format is LMhash:NThash')
    cred.add_argument('--aes-key', dest="auth_key", action="store", metavar="hex key", help='AES key to use for Kerberos Authentication (128 or 256 bits)')
    secret.add_argument("-k", "--kerberos", dest="use_kerberos", action="store_true", help='Use Kerberos authentication. Grabs credentials from .ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    return args


if __name__ == '__main__':
    args = parse_args()

    print("[+]======================================================")
    print("[+]    LDAP search console v1.1        @podalirius_      ")
    print("[+]======================================================")
    print()

    auth_lm_hash = ""
    auth_nt_hash = ""
    if args.auth_hashes is not None:
        if ":" in args.auth_hashes:
            auth_lm_hash = args.auth_hashes.split(":")[0]
            auth_nt_hash = args.auth_hashes.split(":")[1]
        else:
            auth_nt_hash = args.auth_hashes

    if args.auth_key is not None:
        args.use_kerberos = True
    
    if args.use_kerberos is True and args.kdcHost is None:
        print("[!] Specify KDC's Hostname of FQDN using the argument --kdcHost")
        exit()
    
    try:
        ldap_server, ldap_session = init_ldap_session(
            auth_domain=args.auth_domain,
            auth_dc_ip=args.dc_ip,
            auth_username=args.auth_username,
            auth_password=args.auth_password,
            auth_lm_hash=auth_lm_hash,
            auth_nt_hash=auth_nt_hash,
            auth_key=args.auth_key,
            use_kerberos=args.use_kerberos,
            kdcHost=args.kdcHost,
            use_ldaps=args.use_ldaps
        )

        logging.info("Authentication successful!")

        dn = ldap_server.info.other["defaultNamingContext"][0]
        lc = LDAPConsole(ldap_server, ldap_session, dn, debug=args.debug)

        last2_query_results, last2_query = {}, ""
        last1_query_results, last1_query = {}, ""

        running = True
        while running:
            try:
                cmd = input("[\x1b[95m%s\x1b[0m]> " % lc.target_dn).strip().split(" ")

                if cmd[0].lower() == "exit":
                    running = False

                elif cmd[0].lower() == "query":
                    _query = ' '.join(cmd[1:]).strip()
                    last2_query = last1_query
                    last1_query = _query
                    if len(_query) == 0:
                        print("\x1b[91mEmpty query.\x1b[0m")
                    else:
                        try:
                            _select_index = [c.lower() for c in cmd].index('select')
                        except ValueError as e:
                            _select_index = -1

                        if _select_index != -1:
                            _query = ' '.join(cmd[1:_select_index]).strip()
                            _attrs = cmd[_select_index + 1:]
                            last2_query_results = last1_query_results
                            last1_query_results = lc.query(_query, attributes=_attrs)
                        else:
                            _query = ' '.join(cmd[1:]).strip()
                            _attrs = ['*']
                            last2_query_results = last1_query_results
                            last1_query_results = lc.query(_query, attributes=_attrs)

                elif cmd[0].lower() == "base":
                    _base = ' '.join(cmd[1:])
                    if '.' in _base:
                        _base = ','.join(["DC=%s" % part for part in _base.split('.')])
                    lc.target_dn = _base

                elif cmd[0].lower() == "diff":
                    # Todo; handle the added and removed DN results
                    common_keys = []
                    for key in last2_query_results.keys():
                        if key in last1_query_results.keys():
                            common_keys.append(key)
                        else:
                            print("[!] key '%s' was deleted in last results." % key)
                    for key in last1_query_results.keys():
                        if key not in last2_query_results.keys():
                            print("[!] key '%s' was added in last results." % key)
                    #
                    for _dn in common_keys:
                        paths_l2 = dict_get_paths(last2_query_results[_dn])
                        paths_l1 = dict_get_paths(last1_query_results[_dn])
                        #
                        attrs_diff = []
                        for p in paths_l1:
                            vl2 = dict_path_access(last2_query_results[_dn], p)
                            vl1 = dict_path_access(last1_query_results[_dn], p)
                            if vl1 != vl2:
                                attrs_diff.append((p, vl1, vl2))
                        #
                        if len(attrs_diff) != 0:
                            # Print DN
                            print(_dn)
                            for _ad in attrs_diff:
                                path, vl1, vl2 = _ad
                                print("    " + "──>".join(["\"\x1b[93m%s\x1b[0m\"" % attr for attr in path]) + ":")
                                if vl1 is not None:
                                    print("    " + "  > " + "Old value:", vl2)
                                else:
                                    print("    " + "  > " + "Old value: None (attribute was not present in the last reponse)")
                                if vl2 is not None:
                                    print("    " + "  > " + "New value:", vl1)
                                else:
                                    print("    " + "  > " + "New value: None (attribute is not present in the reponse)")

                elif cmd[0].lower() == "presetquery":
                    if cmd[1] == "get_all_users":
                        _query = "(&(objectCategory=person)(objectClass=user))"
                        _attrs = ["objectSid", "sAMAccountName"]
                        last2_query_results = last1_query_results
                        last1_query_results = lc.query(_query, attributes=_attrs, quiet=True)
                        if len(last1_query_results.keys()) != 0:
                            for key in last1_query_results.keys():
                                user = last1_query_results[key]
                                _sAMAccountName = user["sAMAccountName"][0].decode('UTF-8')
                                _sid = format_sid(user["objectSid"][0])
                                print(" | \x1b[93m%-25s\x1b[0m : \x1b[96m%s\x1b[0m" % (_sAMAccountName, _sid))
                        else:
                            print("\x1b[91mNo results.\x1b[0m")

                    elif cmd[1] == "get_all_kerberoastables":
                        _query = "(&(objectClass=user)(servicePrincipalName=*)(!(objectClass=computer))(!(cn=krbtgt))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
                        _attrs = ['sAMAccountName', 'servicePrincipalName']
                        last2_query_results = last1_query_results
                        last1_query_results = lc.query(_query, attributes=_attrs, quiet=True)
                        if len(last1_query_results.keys()) != 0:
                            for key in last1_query_results.keys():
                                user = last1_query_results[key]
                                _sAMAccountName = user["sAMAccountName"][0].decode('UTF-8')
                                for spn in user["servicePrincipalName"]:
                                    print(" | \x1b[93m%-25s\x1b[0m : \x1b[96m%-30s\x1b[0m" % (_sAMAccountName, spn.decode('UTF-8')))
                        else:
                            print("\x1b[91mNo results.\x1b[0m")
                    elif cmd[1] == "get_all_descriptions":
                        _query = "(&(objectCategory=person)(objectClass=user)(description=*))"
                        _attrs = ["description", "sAMAccountName"]
                        last2_query_results = last1_query_results
                        last1_query_results = lc.query(_query, attributes=_attrs, quiet=True)
                        if len(last1_query_results.keys()) != 0:
                            for key in last1_query_results.keys():
                                user = last1_query_results[key]
                                _sAMAccountName = user["sAMAccountName"][0].decode('UTF-8')
                                _description = user["description"][0].decode('UTF-8')
                                print(" | \x1b[93m%-25s\x1b[0m : \x1b[96m%s\x1b[0m" % (_sAMAccountName, _description))
                        else:
                            print("\x1b[91mNo results.\x1b[0m")
                    else:
                        pass
                elif cmd[0].lower() == "help":
                    print_help()
                else:
                    print("Unknown command. Type 'help' for help.")
            except KeyboardInterrupt as e:
                print()
                running = False
            except EOFError as e:
                print()
                running = False

    except Exception as e:
        if args.debug:
            traceback.print_exc()
        logging.warning(str(e))
