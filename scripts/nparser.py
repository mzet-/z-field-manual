#!/bin/usr/python3
#
# Parts of code based on:
# https://github.com/x90skysn3k/brutespray/blob/master/brutespray.py
#
# Suppported services names: 
# cat /usr/share/nmap/nmap-service-probes | grep -v '^[#].*' | grep -v '^[[:space:]]*$' | grep match | cut -d' ' -f2 | sort -u
# TODO:Use generic name 'https' for possible names of https services:
# https
# https-alt
# https?
# https-alt?
# ssl|http
# ssl|https
# ssl|https?
# ssl|https-alt
# ssl|https-alt?
# .+-https
# .+-https?
# ssl|.+-http
# ssl|.+-https
# ssl|.+-http?
# ssl|.+-https?
#
# For 'http':
# http
# http?
# http-alt
# http-alt?
# http-proxy
# http-proxy?
# .+-http
# .+-http?
#
# TODO: UDP support
# TODO: colors

import argparse
import re
import os
import sys

def prep_http_regex():
    return r'([0-9][0-9]*)/open/[a-z][a-z]*//http'

def find_services(gnfile, services):
    results = []

    with open(gnfile, 'r') as gnmap_file:
        for line in gnmap_file:
            try:
                ip = re.findall( r'[0-9]+(?:\.[0-9]+){3}', line)[0]

                for service in services:
                    if service == "http":
                        regex_pattern = prep_http_regex()
                        rx = re.compile(regex_pattern)
                    else:
                        rx = re.compile(r'([0-9][0-9]*)/open/[a-z][a-z]*//' + service)

                    try:
                        matches = rx.findall(line)

                        if matches and ip not in results:
                            results.append(ip)

                        if args.list:
                            for i in matches:
                                print(ip + ":" + i)
                    except:
                        continue
            except:
                continue

    return results

def find_ports(gnfile, ports):
    results = []
    unique_results = []

    with open(gnfile, 'r') as gnmap_file:
        content = gnmap_file.read()
        for port in ports:
            rx = re.compile(r'Host: ([0-9]+(?:\.[0-9]+){3}).+ ' + port + r'/open/[a-z][a-z]*//')
            try:
                matches = rx.findall(content)
                if args.list:
                    for i in matches:
                        print(i + ":" + port)
                else:
                    results += matches
            except:
                continue

    # remove duplicates
    if not args.list:
        for element in results:
            if element not in unique_results:
                unique_results.append(element)

    return unique_results

def display_hosts(nfile, hosts):

    with open(nfile, 'r') as nmap_file:
        content = nmap_file.read()

        for host in hosts:
            rx = re.compile(r'Nmap scan report for ' + host + r'(.*?)(?:Nmap scan report for|# Nmap done at)', re.DOTALL)
            try:
                block = rx.findall(content)[0]

                # remove 'unrecognized service' blocks
                rx2 = re.compile(r'==============NEXT SERVICE FINGERPRINT \(SUBMIT INDIVIDUALLY\)==============(.*?)\);', re.DOTALL)
                block = rx2.sub("=== UNRECOGNIZED SERVICE FINGERPRINT removed for brevity ===", block)

                rx3 = re.compile(r'SF-(.*?)\);', re.DOTALL)
                block = rx3.sub("=== UNRECOGNIZED SERVICE FINGERPRINT removed for brevity ===", block)

                # display it
                print('---------------------------------------------------------------------------------')
                print(host)
                print('---------------------------------------------------------------------------------')
                print(block)
            except:
                continue


def parse_args():
    parser = argparse.ArgumentParser(description="Usage: python nparser.py <OPTIONS> [IPs] OR [ports]\n")

    menu_group = parser.add_argument_group('Menu Options')
    menu_group.add_argument('-f', '--file', help="NMAP and GNMAP file to parse", required=True, default=None)
    menu_group.add_argument('-i', '--hosts', help="Hosts (IPs) to display", required=False, default=None)
    menu_group.add_argument('-p', '--ports', help="Display machines with those ports opened", required=False, default=None)
    menu_group.add_argument('-s', '--services', help="Display machines with those service available", required=False, default=None)
    menu_group.add_argument('-l', '--list', help="Show only minimal greppable output", action='store_const', const=sum, required=False, default=None)

    args = parser.parse_args()

    if args.hosts is None and args.ports is None and args.services is None:
        parser.error("arguments -i/--hosts OR -p/--ports OR -s/--services are required")

    if args.hosts is not None and args.ports is not None:
        parser.error("arguments -i/--hosts and -p/--ports are mutually exclusive")

    if args.hosts is not None and args.services is not None:
        parser.error("arguments -i/--hosts and -s/--services are mutually exclusive")

    if args.ports is not None and args.services is not None:
        parser.error("arguments -p/--ports and -s/--services are mutually exclusive")

    return args

if __name__ == "__main__":

    ports = []
    hosts = []
    services = []

    args = parse_args()
    
    if args.file:
        filename = args.file
        if not os.path.isfile(filename + ".nmap"):
            sys.stderr.write("No " + filename + ".nmap file found. Aborting.\n")
            exit(1)
        if not os.path.isfile(filename + ".gnmap"):
            sys.stderr.write("No " + filename + ".gnmap file found. Aborting.\n")
            exit(1)

    if args.hosts:
        hosts = args.hosts.split(",")

    if args.ports:
        ports = args.ports.split(",")

    if args.services:
        services = args.services.split(",")


    if ports:
        hosts = find_ports(filename + ".gnmap", ports)

    if services:
        hosts = find_services(filename + ".gnmap", services)

    if hosts and args.list == None:
        display_hosts(filename + ".nmap", hosts)
