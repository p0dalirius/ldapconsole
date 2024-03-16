#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : ldapsearch.py
# Author             : Podalirius (@podalirius_)
# Date created       : 29 Jul 2021

import readline
import argparse
from ldap3.protocol.formatters.formatters import format_sid
import ldap3
from sectools.windows.ldap import init_ldap_session
from sectools.windows.crypto import parse_lm_nt_hashes
import os
import traceback
import sys
import xlsxwriter


VERSION = "2.0.2"


class CommandCompleter(object):
    """
    Class for handling command completion in the LDAP console.
    """
    def __init__(self):
        self.options = {
            "diff": [],
            "query": [],
            "presetquery": ["all_users", "all_groups", "all_kerberoastables", "all_descriptions"],
            "help": [],
            "infos": [],
            "searchbase": [],
            "exit": []
        }

    def complete(self, text, state):
        """
        Function to handle command completion in the LDAP console.

        This function completes the user's input based on the available options for commands in the LDAP console.

        Args:
            text (str): The current text input by the user.
            state (int): The current state of completion.

        Returns:
            str: The next completion suggestion based on the user's input state.
        """
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

# LDAP controls
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/3c5e87db-4728-4f29-b164-01dd7d7391ea
LDAP_PAGED_RESULT_OID_STRING = "1.2.840.113556.1.4.319"
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/f14f3610-ee22-4d07-8a24-1bf1466cba5f
LDAP_SERVER_NOTIFICATION_OID = "1.2.840.113556.1.4.528"

class LDAPSearcher(object):
    """
    LDAPSearcher class for executing LDAP queries with pagination and notification control.

    This class provides methods to perform LDAP search operations with support for pagination to handle large datasets.
    It also offers the option to enable notification control to receive updates about changes in the LDAP directory.

    Attributes:
    - ldap_server (str): The LDAP server to connect to.
    - ldap_session (ldap3.Connection): The LDAP session to use for executing queries.

    Methods:
    - query(base_dn, query, attributes=['*'], page_size=1000): Executes an LDAP query with optional notification control.

    Raises:
    - ldap3.core.exceptions.LDAPInvalidFilterError: If the provided query string is not a valid LDAP filter.
    - Exception: For any other issues encountered during the search operation.
    """
    def __init__(self, ldap_server, ldap_session):
        super(LDAPSearcher, self).__init__()
        self.ldap_server = ldap_server
        self.ldap_session = ldap_session

    def query(self, base_dn, query, attributes=['*'], page_size=1000):
        """
        Executes an LDAP query with optional notification control.

        This method performs an LDAP search operation based on the provided query and attributes. It supports
        pagination to handle large datasets and can optionally enable notification control to receive updates
        about changes in the LDAP directory.

        Parameters:
        - query (str): The LDAP query string.
        - attributes (list of str): A list of attribute names to include in the search results. Defaults to ['*'], which returns all attributes.
        - notify (bool): If True, enables the LDAP server notification control to receive updates about changes. Defaults to False.

        Returns:
        - dict: A dictionary where each key is a distinguished name (DN) and each value is a dictionary of attributes for that DN.

        Raises:
        - ldap3.core.exceptions.LDAPInvalidFilterError: If the provided query string is not a valid LDAP filter.
        - Exception: For any other issues encountered during the search operation.
        """

        results = {}
        try:
            # https://ldap3.readthedocs.io/en/latest/searches.html#the-search-operation
            paged_response = True
            paged_cookie = None
            while paged_response == True:
                self.ldap_session.search(
                    base_dn,
                    query,
                    attributes=attributes,
                    size_limit=0,
                    paged_size=page_size,
                    paged_cookie=paged_cookie
                )
                if "controls" in self.ldap_session.result.keys():
                    if LDAP_PAGED_RESULT_OID_STRING in self.ldap_session.result["controls"].keys():
                        next_cookie = self.ldap_session.result["controls"][LDAP_PAGED_RESULT_OID_STRING]["value"]["cookie"]
                        if len(next_cookie) == 0:
                            paged_response = False
                        else:
                            paged_response = True
                            paged_cookie = next_cookie
                    else:
                        paged_response = False
                else:
                    paged_response = False
                for entry in self.ldap_session.response:
                    if entry['type'] != 'searchResEntry':
                        continue
                    results[entry['dn']] = entry["attributes"]
        except ldap3.core.exceptions.LDAPInvalidFilterError as e:
            print("Invalid Filter. (ldap3.core.exceptions.LDAPInvalidFilterError)")
        except Exception as e:
            raise e
        return results

    def query_all_naming_contexts(self, query, attributes=['*'], page_size=1000):
        """
        Queries all naming contexts on the LDAP server with the given query and attributes.

        This method iterates over all naming contexts retrieved from the LDAP server's information,
        performing a paged search for each context using the provided query and attributes. The results
        are aggregated and returned as a dictionary where each key is a distinguished name (DN) and
        each value is a dictionary of attributes for that DN.

        Parameters:
        - query (str): The LDAP query to execute.
        - attributes (list of str): A list of attribute names to retrieve for each entry. Defaults to ['*'] which fetches all attributes.

        Returns:
        - dict: A dictionary where each key is a DN and each value is a dictionary of attributes for that DN.
        """

        results = {}
        try:
            for naming_context in self.ldap_server.info.naming_contexts:
                paged_response = True
                paged_cookie = None
                while paged_response == True:
                    self.ldap_session.search(
                        naming_context,
                        query,
                        attributes=attributes,
                        size_limit=0,
                        paged_size=page_size,
                        paged_cookie=paged_cookie
                    )
                    if "controls" in self.ldap_session.result.keys():
                        if LDAP_PAGED_RESULT_OID_STRING in self.ldap_session.result["controls"].keys():
                            next_cookie = self.ldap_session.result["controls"][LDAP_PAGED_RESULT_OID_STRING]["value"]["cookie"]
                            if len(next_cookie) == 0:
                                paged_response = False
                            else:
                                paged_response = True
                                paged_cookie = next_cookie
                        else:
                            paged_response = False
                    else:
                        paged_response = False
                    for entry in self.ldap_session.response:
                        if entry['type'] != 'searchResEntry':
                            continue
                        results[entry['dn']] = entry["attributes"]
        except ldap3.core.exceptions.LDAPInvalidFilterError as e:
            print("Invalid Filter. (ldap3.core.exceptions.LDAPInvalidFilterError)")
        except Exception as e:
            raise e
        return results

    def print_colored_result(self, dn, data):
        """
        This function prints the provided distinguished name (DN) and associated data in a colored and structured format.

        Parameters:
        - dn (str): The distinguished name (DN) of the LDAP entry.
        - data (dict): A dictionary containing the attributes associated with the provided DN.

        Returns:
        - None
        """
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
        print("│ %s" % dn)
        _parse_print(data, prompt=['    ', '    '])


class PresetQueries(object):
    """
    Class to store preset LDAP queries for common search operations.

    Attributes:
        preset_queries (dict): A dictionary containing preset queries with descriptions and filters.
    
    Methods:
        __init__(ldapSearcher): Constructor method to initialize the PresetQueries class with an LDAP searcher.
        perform(command, arguments): Method to perform a specific preset query based on the given command.
    """

    preset_queries = {
        "all_users": {
            "description": "Get the list of all users.",
            "filter": "(&(objectCategory=person)(objectClass=user))",
            "attributes": ["objectSid", "sAMAccountName"]
        },
        "all_descriptions": {
            "description": "Get the descriptions of all users.",
            "filter": "(&(objectCategory=person)(objectClass=user)(description=*))",
            "attributes": ["sAMAccountName", "description"]
        },
        "all_groups": {
            "description": "Get the list of all groups.",
            "filter": "(objectClass=group)",
            "attributes": ["distinguishedName"]
        },
        "all_computers": {
            "description": "Get the list of all computers.",
            "filter": "(objectClass=computer)",
            "attributes": ["distinguishedName"]
        },
        "all_organizational_units": {
            "description": "Get the list of all organizationalUnits.",
            "filter": "(objectClass=organizationalUnit)",
            "attributes": ["distinguishedName"]
        }
    }
    
    def __init__(self, ldapSearcher):
        self.ldapSearcher = ldapSearcher

    def perform(self, command, arguments):
        """
        Method to perform a specific preset query based on the given command.

        Args:
            command (str): The command specifying the preset query to be performed.
            arguments (list): Additional arguments for the query.

        Returns:
            None
        """
        if command in self.preset_queries.keys():
            if command == "all_users":
                self.get_all_users()

            elif command == "all_descriptions":
                self.get_all_descriptions()
            
            elif command == "all_kerberoastables":
                _query = "(&(objectClass=user)(servicePrincipalName=*)(!(objectClass=computer))(!(cn=krbtgt))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
                _attrs = ['sAMAccountName', 'servicePrincipalName']
                last2_query_results = last1_query_results
                last1_query_results = self.ldapSearcher.query(_query, attributes=_attrs, quiet=True)
                if len(last1_query_results.keys()) != 0:
                    for key in last1_query_results.keys():
                        user = last1_query_results[key]
                        _sAMAccountName = user["sAMAccountName"][0].decode('UTF-8')
                        for spn in user["servicePrincipalName"]:
                            print(" | \x1b[93m%-25s\x1b[0m : \x1b[96m%-30s\x1b[0m" % (_sAMAccountName, spn.decode('UTF-8')))
                else:
                    print("\x1b[91mNo results.\x1b[0m")
                    
            elif command == "all_descriptions":
                _query = "(&(objectCategory=person)(objectClass=user)(description=*))"
                _attrs = ["description", "sAMAccountName"]
                last2_query_results = last1_query_results
                last1_query_results = self.ldapSearcher.query(_query, attributes=_attrs, quiet=True)
                if len(last1_query_results.keys()) != 0:
                    for key in last1_query_results.keys():
                        user = last1_query_results[key]
                        _sAMAccountName = user["sAMAccountName"][0].decode('UTF-8')
                        _description = user["description"][0].decode('UTF-8')
                        print(" | \x1b[93m%-25s\x1b[0m : \x1b[96m%s\x1b[0m" % (_sAMAccountName, _description))
                else:
                    print("\x1b[91mNo results.\x1b[0m")
        
        else:
            print("[!] Unknown preset query '%s'. Here is a list of the available preset queries:" % command)
            self.print_help()

    def get_all_users(self, attributes=["objectSid", "sAMAccountName"]):
        """
        Method to retrieve all users from LDAP with specified attributes.

        Args:
            attributes (list): List of attributes to retrieve for each user. Default is ["objectSid", "sAMAccountName"].

        Returns:
            None
        """
        results = self.ldapSearcher.query_all_naming_contexts(
            query=self.preset_queries["all_users"]["filter"],
            attributes=self.preset_queries["all_users"]["attributes"]
        )
        if len(results.keys()) != 0:
            if attributes == ["objectSid", "sAMAccountName"]:
                for distinguishedName in results.keys():
                    _sAMAccountName = results[distinguishedName]["sAMAccountName"][0].decode('UTF-8')
                    _sid = format_sid(results[distinguishedName]["objectSid"][0])
                    print(" | \x1b[93m%-25s\x1b[0m : \x1b[96m%s\x1b[0m" % (_sAMAccountName, _sid))
            else:
                for distinguishedName in results.keys():
                    print("[+] %s" % distinguishedName)
                    for attrName in attributes:
                        print(" | %s : %s" % (attrName, results[distinguishedName][attrName][0].decode('UTF-8')))
        else:
            print("\x1b[91mNo results.\x1b[0m")

    def get_all_descriptions(self):
        """
        Method to retrieve all descriptions from LDAP.

        This method queries LDAP to retrieve all users with descriptions and prints out their sAMAccountName and description.
        If no results are found, it prints a message indicating no results.

        Args:
            None

        Returns:
            None
        """
        results = self.ldapSearcher.query_all_naming_contexts(
            query=self.preset_queries["all_descriptions"]["filter"],
            attributes=self.preset_queries["all_descriptions"]["attributes"]
        )

        if len(results.keys()) != 0:
            for distinguishedName in results.keys():
                _sAMAccountName = results[distinguishedName]["sAMAccountName"]
                _description = format_sid(results[distinguishedName]["description"][0])
                print(" | \x1b[93m%-25s\x1b[0m : \x1b[96m%s\x1b[0m" % (_sAMAccountName, _description))
        else:
            print("\x1b[91mNo results.\x1b[0m")

    def print_help(self):
        """
        Method to print the available preset queries along with their descriptions and LDAP filters.

        Args:
            None

        Returns:
            None
        """
        for command in self.preset_queries.keys():
            print(" - %-15s %s. (LDAP Filter: %s)" % (command, self.preset_queries[command]["description"], self.preset_queries[command]["filter"]))


def print_help():
    """
    Function to print the available commands and their descriptions.

    Args:
        None

    Returns:
        None
    """
    print(" - %-15s %s " % ("base", "Sets LDAP base DN."))
    print(" - %-15s %s " % ("diff", "Show the differences between the last two requests."))
    print(" - %-15s %s " % ("query", "Sends a query to LDAP."))
    print(" - %-15s %s " % ("presetquery", "Use a builtin preset query."))
    print(" - %-15s %s " % ("help", "Displays this help message."))
    print(" - %-15s %s " % ("exit", "Exits the script."))
    return


def parseArgs():
    parser = argparse.ArgumentParser(add_help=True, description="LDAP console")
    parser.add_argument("--use-ldaps", action="store_true", help="Use LDAPS instead of LDAP")
    parser.add_argument("--debug", dest="debug", action="store_true", default=False, help="Debug mode")
    parser.add_argument("--quiet", dest="quiet", action="store_true", default=False, help="Quiet mode")

    parser.add_argument("-q", "--query", dest="query", default=None, type=str, help="LDAP query")
    parser.add_argument("-a", "--attribute", dest="attributes", default=[], action="append", type=str, help="Attributes to extract.")

    parser.add_argument("-x", "--xlsx", dest="xlsx", default=None, type=str, help="Output results to an XLSX file.")

    authconn = parser.add_argument_group("authentication & connection")
    authconn.add_argument("--dc-ip", action="store", metavar="ip address", help="IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted it will use the domain part (FQDN) specified in the identity parameter")
    authconn.add_argument("--kdcHost", dest="kdcHost", action="store", metavar="FQDN KDC", help="FQDN of KDC for Kerberos.")
    authconn.add_argument("-d", "--domain", dest="auth_domain", metavar="DOMAIN", action="store", help="(FQDN) domain to authenticate to")
    authconn.add_argument("-u", "--user", dest="auth_username", metavar="USER", action="store", help="user to authenticate with")

    secret = parser.add_argument_group()
    cred = secret.add_mutually_exclusive_group()
    cred.add_argument("--no-pass", action="store_true", help="Don't ask for password (useful for -k)")
    cred.add_argument("-p", "--password", dest="auth_password", metavar="PASSWORD", action="store", help="password to authenticate with")
    cred.add_argument("-H", "--hashes", dest="auth_hashes", action="store", metavar="[LMHASH:]NTHASH", help="NT/LM hashes, format is LMhash:NThash")
    cred.add_argument("--aes-key", dest="auth_key", action="store", metavar="hex key", help="AES key to use for Kerberos Authentication (128 or 256 bits)")
    secret.add_argument("-k", "--kerberos", dest="use_kerberos", action="store_true", help="Use Kerberos authentication. Grabs credentials from .ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    return args


if __name__ == '__main__':
    options = parseArgs()

    if not options.quiet:
        print("LDAPconsole v%s - by @podalirius_\n" % VERSION)

    # Parse hashes
    if options.auth_hashes is not None:
        if ":" not in options.auth_hashes:
            options.auth_hashes = ":" + options.auth_hashes
    auth_lm_hash, auth_nt_hash = parse_lm_nt_hashes(options.auth_hashes)
    
    # Use AES Authentication key if available
    if options.auth_key is not None:
        options.use_kerberos = True
    if options.use_kerberos is True and options.kdcHost is None:
        print("[!] Specify KDC's Hostname of FQDN using the argument --kdcHost")
        exit()
    
    # Try to authenticate with specified credentials
    try:
        if not options.quiet:
            print("[>] Try to authenticate as '%s\\%s' on %s ... " % (options.auth_domain, options.auth_username, options.dc_ip))
        ldap_server, ldap_session = init_ldap_session(
            auth_domain=options.auth_domain,
            auth_dc_ip=options.dc_ip,
            auth_username=options.auth_username,
            auth_password=options.auth_password,
            auth_lm_hash=auth_lm_hash,
            auth_nt_hash=auth_nt_hash,
            auth_key=options.auth_key,
            use_kerberos=options.use_kerberos,
            kdcHost=options.kdcHost,
            use_ldaps=options.use_ldaps
        )
        if not options.quiet:
            print("[+] Authentication successful!\n")

        search_base = ldap_server.info.other["defaultNamingContext"][0]
        ls = LDAPSearcher(ldap_server=ldap_server, ldap_session=ldap_session)

        # Single query inline
        if options.query is not None:
            results = ls.query(
                base_dn=search_base,
                query=options.query,
                attributes=options.attributes
            )

            if options.xlsx is not None:
                print("[>] Exporting %d results to %s ... " % (len(list(results.keys())), options.xlsx), end="")
                sys.stdout.flush()

                basepath = os.path.dirname(options.xlsx)
                filename = os.path.basename(options.xlsx)
                if basepath not in [".", ""]:
                    if not os.path.exists(basepath):
                        os.makedirs(basepath)
                    path_to_file = basepath + os.path.sep + filename
                else:
                    path_to_file = filename
                
                # https://xlsxwriter.readthedocs.io/workbook.html#Workbook
                workbook_options = {
                    'constant_memory': True, 
                    'in_memory': True, 
                    'strings_to_formulas': False,
                    'remove_timezone': True
                }
                workbook = xlsxwriter.Workbook(filename=path_to_file, options=workbook_options)
                worksheet = workbook.add_worksheet()
                
                if '*' in options.attributes:
                    attributes = []
                    options.attributes.remove('*')
                    attributes += options.attributes
                    first_dn = list(results.keys())[0]
                    for dn in results.keys():
                        attributes = sorted(list(set(attributes + list(results[dn].keys()))))
                else:
                    attributes = options.attributes

                header_format = workbook.add_format({'bold': 1})
                header_fields = ["distinguishedName"] + attributes
                for k in range(len(header_fields)):
                    worksheet.set_column(k, k + 1, len(header_fields[k]) + 3)
                worksheet.set_row(0, 20, header_format)
                worksheet.write_row(0, 0, header_fields)

                row_id = 1
                for distinguishedName in results.keys():
                    data = [distinguishedName]
                    for attr in attributes:
                        if attr in results[distinguishedName].keys():
                            value = results[distinguishedName][attr]
                            if type(value) == str:
                                data.append(value)
                            elif type(value) == bytes:
                                data.append(str(value))
                            elif type(value) == list:
                                data.append('\n'.join([str(l) for l in value]))
                            else:
                                data.append(str(value))
                        else:
                            data.append("")
                    worksheet.write_row(row_id, 0, data)
                    row_id += 1

                worksheet.autofilter(0, 0, row_id, len(header_fields) - 1)
                workbook.close()

            else:
                for dn in sorted(list(results.keys())):
                    ls.print_colored_result(dn=dn, data=results[dn])

            print("done.")

        # Live console
        else:
            last2_query_results, last2_query = {}, ""
            last1_query_results, last1_query = {}, ""

            running = True
            while running:
                try:
                    userinput = input("[\x1b[95m%s\x1b[0m]> " % search_base).strip().split(" ")
                    command, arguments = userinput[0].lower(), userinput[1:]

                    if command == "exit":
                        running = False

                    elif command == "query":
                        _query = ' '.join(arguments[0:]).strip()
                        last2_query = last1_query
                        last1_query = _query
                        if len(_query) == 0:
                            print("\x1b[91m[!] Empty query.\x1b[0m")
                        else:
                            try:
                                _select_index = [c.lower() for c in arguments].index('select')
                            except ValueError as e:
                                _select_index = -1

                            if _select_index != -1:
                                _query = ' '.join(arguments[0:_select_index]).strip()
                                _attrs = arguments[_select_index + 1:]
                            else:
                                _query = ' '.join(arguments[0:]).strip()
                                _attrs = ['*']

                            last2_query_results = last1_query_results
                            last1_query_results = ls.query(base_dn=search_base, query=_query, attributes=_attrs)

                            for dn in sorted(list(last1_query_results.keys())):
                                ls.print_colored_result(dn=dn, data=last1_query_results[dn])
                            
                            print("└──> LDAP query returned %d results." % len(last1_query_results.keys()))

                    elif command == "searchbase":
                        __searchbase = ' '.join(arguments)
                        if '.' in __searchbase:
                            __searchbase = ','.join(["DC=%s" % part for part in __searchbase.split('.')])
                        search_base = __searchbase

                    # Displays the difference between this query results and the results of the query before
                    elif command == "diff":
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

                    # 
                    elif command == "presetquery":
                        pq = PresetQueries(ldapSearcher=ls)
                        pq.perform(command=arguments[0], arguments=arguments[1:])
                    
                    # Display help
                    elif command == "help":
                        print_help()

                    # Fallback to unknown command
                    else:
                        print("Unknown command. Type 'help' for help.")

                except KeyboardInterrupt as e:
                    print()
                    running = False

                except EOFError as e:
                    print()
                    running = False

    except Exception as e:
        if options.debug:
            traceback.print_exc()
        print("[!] Error: %s" % str(e))
