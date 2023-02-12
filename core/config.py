from uuid import uuid4
from pathlib import Path
import argparse
from sys import exit
import os
import json
from re import search

from axiom.axiomy import Axiomy
#----------------------------------------------------------------------------------------------------------------------------------#
def configure():

    SCAN_ID = str(uuid4())
    HOME_DIR = str(Path.home())
    DNSCEWL_CORRECT_CONFIG = [{"command":"/usr/bin/DNSCewl --level 2 --range 10 -i --tL input -p _wordlist_ --subs --no-color | tail -n +14 | tee output", "ext":"txt"}]
    MEG_CORRECT_CONFIG = [{"command":"/home/op/go/bin/meg -v _wordlist_ input output", "ext":""}]

    #Set and parse command line arguments.
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target-file", help=f'Absolute path to hosts file to scan, for example "{HOME_DIR}/hosts.txt".\nThe text file given here should be contain 1 host per line formatted like "example.com".', type=str, required=True)
    parser.add_argument("-i", "--instances", help=f'Number of Axiom instances to generate.', type=int, choices=range(1,14), required=True)
    parser.add_argument("-n", "--name", help="Name of the scan - no special characters as the output will be saved under this name.", type=str, default='asuna')
    parser.add_argument("-r", "--runtime", help="Max runtime allowed per Axiom scan - useful during testing.", type=str, default=None)
    parser.add_argument("-w", "--wordlists", help=f'Path to default wordlist directory. This directory should contain 2 files: "dns.txt" and "ffuf.txt".\nEach file will be the default wordlist given to that respective tool. Default is "wordlists/".', type=str, default='wordlists/')
    args = parser.parse_args()

    HOSTS_PATH = f'{args.target_file}'
    DEFAULT_PATH = f'/{HOME_DIR}/{args.name + "-" + SCAN_ID}/'
    DNS_WORDLIST_PATH = f'{args.wordlists}/dns.txt'
    FFUF_WORDLIST_PATH = f'{args.wordlists}/ffuf.txt'

    print('[INFO] Checking health...\n')
    
    #Create output directory.
    if os.path.exists(DEFAULT_PATH): 
        print('[ERROR] Please choose a new, unique name for the scan.') 
        exit(1)
    try:
        os.makedirs(DEFAULT_PATH)
    except:
        print('[ERROR] Unable to create ouput directory. Please give a new scan name without "\\" or "/" characters.')
        exit(1)
    
    #Check that default wordlists exist.
    if not os.path.exists(DNS_WORDLIST_PATH): 
        print(f'[ERROR] Unable to read dns default wordlist at "wordlists/dns.txt".\n Please ensure that it exists in the correct path.')
        exit(1)
    if not os.path.exists(FFUF_WORDLIST_PATH):
        print(f'[ERROR] Unable to read ffuf default wordlist at "wordlists/ffuf.txt".\n Please ensure that it exists in the correct path.')
        exit(1)
    
    #Check that DNSCewl json module is compatible.
    try:
        with open(f'{HOME_DIR}/.axiom/modules/dnscewl.json','r+') as dns:
            if json.dumps(DNSCEWL_CORRECT_CONFIG) not in dns.read():
                answer = input(f'Your DNSCewl json module at {HOME_DIR}/.axiom/modules/dnscewl.json is not compatible with this script.\nWould you like you automatically update it to be compatible? (y/n)')
                if answer.lower() == 'y' or answer.lower() == 'yes':
                    try:
                        dns.seek(0)
                        dns.truncate(0)
                        dns.write(json.dumps(DNSCEWL_CORRECT_CONFIG))
                        print('Module updated succesfully.\n')
                    except:
                        print(f'Unable to edit DNSCewl module json at {HOME_DIR}/.axiom/modules/dnscewl.json.\nTry removing the "-p" flag.')
                        exit(1)
                else:
                    print('Please manually update ~/.axiom/modules/dnscewl.json.\nHint: Try removing the "-p" flag.')
                    exit(1)
    except:
        print(f'Unable to read DNSCewl module json at {HOME_DIR}/.axiom/modules/dnscewl.json.\nPlease ensure it exists in the correct path.')
        exit(1)
    
    #Check that Meg json module is compatible.
    try:
        with open(f'{HOME_DIR}/.axiom/modules/meg.json','r+') as meg:
            if json.dumps(MEG_CORRECT_CONFIG) not in meg.read():
                answer = input(f'Your Meg json module at {HOME_DIR}/.axiom/modules/meg.json is not compatible with this script.\nWould you like you automatically update it to be compatible? (y/n)')
                if answer.lower() == 'y' or answer.lower() == 'yes':
                    try:
                        meg.truncate(0)
                        meg.write(json.dumps(MEG_CORRECT_CONFIG))
                        print('Module updated succesfully.\n')
                    except:
                        print(f'Unable to edit Meg module json at {HOME_DIR}/.axiom/modules/meg.json.\nTry changing the "/" to "_wordlist_".')
                        exit(1)
                else:
                    print('Please change your Meg module file to be compatible with this script.\nHint: try changing the "/" to "_wordlist_".')
                    exit(1)
    except:
        print(f'Unable to open Meg module json at "{HOME_DIR}/.axiom/modules/meg.json".\nPlease ensure it exists in the correct path.')
        exit(1)
    
    #Check that host file is a valid file and properly formatted.
    try:
        with open(args.target_file, 'r') as file:
            if search('^[a-zA-Z0-9.-]*$', file.read()):
                print('Target hosts file is formatted incorrectly.\nPlease remove any protocols or ":" "/" characters.\n Use "-h" for more help.')
                exit(1)
    
    except:
        print(f'Unable to read target hosts file at "{args.target_file}". Please use "-h" to check the correct formatting.')
        exit(1)
    
    return {'args': args, 'default path': DEFAULT_PATH, 'hosts path': HOSTS_PATH, 'dns wordlist path': DNS_WORDLIST_PATH, 'ffuf wordlist path': FFUF_WORDLIST_PATH}
#----------------------------------------------------------------------------------------------------------------------------------#
def fleet(config):
    if config:
        args = config['args']
        #Initialize 'axiom' object and test if Axiom is installed.
        try:
            axiom = Axiomy()
        except Exception as e:
            print(e)
       
        #Create Axiom fleet 'asuna' with variable amount of instances (up to 14 currently supported).
        try:
            axiom.fleet(args.name, args.instances)
            print('\n')
        except:
            print(f'[ERROR] Failed to start fleet "{args.name}". Try with default name "asuna".')
            exit(1)
        
        #Select 'asuna' fleet.
        try:
            axiom.select(args.name, wildcard=True)
            print('[INFO] Starting subdomain enumeration.\n')
        except:
            print(f'[ERROR] Failed to select fleet "{args.name}". Please try again with a new name.')
            exit(1)

        return axiom
#----------------------------------------------------------------------------------------------------------------------------------#
def default_scan(axiom, target, module, wordlist, path, runtime, raw=None):
    if os.path.exists(str(target)):
        try:
            print(f'[{str(module).upper()}] Scan started.')
            scan = axiom.scan(target, module, wordlist, path, runtime, str(raw) if raw else None)
            print(f'[{str(module).upper()}] Scan completed.\n')
            return scan
        except:
            print(f'[{str(module).upper()}] Error running "{module}".\n')
            return None, 1
    else:
        print(f'[{str(module).upper()}] Target file "{target}" does not exist. Skipping scan.\n')
        return None, 1
#----------------------------------------------------------------------------------------------------------------------------------#
def shutdown(args, axiom):
    try:
        print(f'[INFO] Deleting fleet "{args.name}".')
        axiom.rm(args.name, wildcard=True)
        print(f'[INFO] Fleet "{args.name}" deleted.\n')
        print("|###|####|####|####|####|####|####|####|####|####|####|####|####|####|####|###|")
        print("|Even If A Monster Beats Me And I Die, I Won't Lose To This Game Or This World|")
        print("|###|####|####|####|####|####|####|####|####|####|####|####|####|####|####|###|")
    except:
        print(f'[ERROR] Unable to delete fleet "{args.name}".')
        exit(1)
#----------------------------------------------------------------------------------------------------------------------------------#