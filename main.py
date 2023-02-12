#!/usr/bin/env python3
#----------------------------------------------------------------------------------------------------------------------------------#
print("|###|####|####|####|####|####|####|####|####|####|####|####|####|####|####|###|")
print("|                                    Asuna!                                   |")
print("|###|####|####|####|####|####|####|####|####|####|####|####|####|####|####|###|\n")
#----------------------------------------------------------------------------------------------------------------------------------#
from urllib.parse import urlparse
import os

from core.config import configure, fleet, default_scan, shutdown
from core.data import txt_to_set, iterable_to_txt, urlor, pathor, subor, paramor
#----------------------------------------------------------------------------------------------------------------------------------#
def main():
    #Create and select Axiom fleet with custom config. 
    config = configure()
    axiom = fleet(config)

    #Data infrastructure (temporary to scan, TODO: Export to database).
    metadata = ['hosts', 'current_hosts_batch', 'subs', 'current_subs_batch', 'alive', 'perms', 'paths', 'urls', 'params']
    data = {}; data = {**data, **dict(zip(metadata, [set() for _ in range(len(metadata))]))}
    paths = {}; paths = {**paths, **dict(zip(metadata, [str(config['default path'] + '/' + label + '.txt') for label in metadata]))}
    txt_to_set(config['hosts path'], data['hosts'])
    iterable_to_txt(paths['hosts'], data['hosts'])

    #Split hosts list into batches sized by instance argument
    hosts_batches = [data['hosts'][i:i + config['args'].instances] for i in range(0, len(data['hosts']), config['args'].instances)]
    for current_hosts_batch in hosts_batches:

        with open(paths['current_hosts_batch'], 'w') as current_hosts_batch_file:
            current_hosts_batch_file.writelines([host + '\n' for host in current_hosts_batch])

        #TODO: USE EXISING SUBS PATHS PARAMS ETC FOR FURTHER DISCOVERY

        #Get all urls.
        default_scan(axiom, paths['current_hosts_batch'], 'gau', None, config['default path'] + 'gau.txt', config['args'].runtime, raw='--subs --blacklist ttf,woff,svg,png --threads 4')
        data['subs'].update(set(subor(config['default path'] + 'gau.txt')))
        data['paths'].update(set(pathor(config['default path'] + 'gau.txt')))
        data['urls'].update(set(urlor(config['default path'] + 'gau.txt')))
        data['params'].update(set(paramor(config['default path'] + 'gau.txt')))
        
        #TODO: Custom config for all tools - especially ENUMERATORS

        #Subdomain enumeration.
        enumerators = {'assetfinder': config['default path'] + 'assetfinder.txt', 
                    'subfinder': config['default path'] + 'subfinder.txt',
                    'amass': config['default path'] + 'amass.txt'}
        default_scan(axiom, paths['current_hosts_batch'], 'assetfinder', None, enumerators['assetfinder'], config['args'].runtime, raw=None)
        default_scan(axiom, paths['current_hosts_batch'], 'subfinder', None, enumerators['subfinder'], config['args'].runtime, raw='--threads 4')
        default_scan(axiom, paths['current_hosts_batch'], 'amass', None, enumerators['amass'], config['args'].runtime, raw='-passive -alts -brute')
        for path in enumerators.values():
            if os.path.exists(path):
                txt_to_set(path, data['subs'])
        iterable_to_txt(paths['subs'], data['subs'])

        #Evenly distribute subdomains list by host so no 1 host is bombarded within same batch
        subs_dict = {host: [[sub for sub in data['subs'] if host in sub], len([sub for sub in data['subs'] if host in sub])] for host in data['hosts'] for sub in data['subs']}
        max_length = max([item[1] for item in subs_dict.values()])
        subs_master = []
        for i in range(max_length):
            for batch in subs_dict.values():
                if (list(batch)[1] / max_length * (i+1)) % 1 == 0:
                    subs_master.append(list(batch)[0].pop())
        data['subs'] = subs_master
 
        #Break subdomains into batches sized by instance argument (nested within host batches)
        subs_batches = [data['subs'][i:i + config['args'].instances] for i in range(0, len(data['subs']), config['args'].instances)]
        for current_subs_batch in subs_batches:

            with open(paths['current_subs_batch'], 'w') as current_subs_batch_file:
                current_subs_batch_file.writelines([sub + '\n' for sub in current_subs_batch])

            #Snapshot current subdomains list and current alive list, composed of pre-discovered subdomains
            pre_dns_cewl_subs = data['subs']

            #Generate DNS permutations wordlist based on subs list and feed to DNSCewl.
            with open(paths['current_subs_batch'],'r') as subs, open(paths['perms'],'w+') as perms, open(config['dns wordlist path'], 'r') as wordlist:
                perms.writelines(set(list(filter(None, ''.join(letter for letter in subs.read().replace('.', '\n')).split('\n') + [word for word in wordlist]))))
            default_scan(axiom, paths['current_subs_batch'], 'dnscewl', paths["perms"], config['default path'] + 'dnscewl.txt', config['args'].runtime, raw=None)

            #TODO: Create temporary DF to delete after batch is complete
            txt_to_set(config['default path'] + 'dnscewl.txt', data['subs'])
            iterable_to_txt(paths['current_subs_batch'], data['subs'])

            #TODO: If alive domain is not in original subs list then VERY INTERESTING
            default_scan(axiom, paths['current_subs_batch'], 'httpx', None, config['default path'] + 'alive.txt', config['args'].runtime, raw=None)
            txt_to_set(config['default path'] + 'alive.txt', data['alive'])

            #Delete leftover permutations
             

        #TODO: If DNSCewl generates a permutation that HTTPX finds to be alive, that is VERY INTERESTING!!!!
        #TODO: DELETE HUGE DNS OUTPUT ONCE ALIVE DOMAINS ARE FOUND

        #TODO: Subdomain takeovers

        #!!!!!! ADD OTHER HUERISITCS - WE NEED MORE EFFICINCY UP TO THIS POINT AND AFTER
        #TODO: AI analyzes screenshots to find interesting subdomains and rank them for efficiency

        #Screenshots.
        default_scan(axiom, paths['alive'], 'gowitness', None, config['default path'] + 'screenshots', config['args'].runtime, raw=None)

        #GoSpider alive urls.
        default_scan(axiom, paths['alive'], 'gospider', None, config['default path'] + 'gospider', config['args'].runtime, raw='-u web -t 4 -d 1 --subs --robots -c 10')
        for file in os.listdir(config['default path'] + 'gospider'):
            if os.path.isfile(config['default path'] + '/gospider/'+ file):
                data['urls'].update(urlor(file))
                data['paths'].update(pathor(file))

        #TODO: Detect backend languages and technologies for FFUF and Kiterunner specific wordlists (php, aspx etc.).
        #In order to do this we need to match subdomains to specific techs which will be hard with axiom.

        #TODO: Analyze found urls of current batch and use certain technologies wordlists to match if one company tends to use php for example.

        #Kiterunner pre-built content discovery.
        default_scan(axiom, paths['alive'], 'krscan', None, config['default path'] + 'kiterunner.txt', config['args'].runtime, raw='-A bak -x 20 -j 200 --fail-status-codes 404,429')
        data['urls'].update(urlor(config['default path'] + 'kiterunner.txt'))
        data['paths'].update(pathor(config['default path'] + 'kiterunner.txt'))

        #TODO: Extract found paths and add to ffuf default wordlist
        iterable_to_txt(config['ffuf wordlist path'], data['paths'], update=True)

        #ffuf.
        default_scan(axiom, paths['alive'], 'ffuf', config['ffuf wordlist path'], config['default path'] + 'ffuf.txt', config['args'].runtime, raw='-recursion --recursion-depth 2 --threads 4 --ignore-body -fc 404,429')
        data['paths'].update(pathor(config['default path'] + 'ffuf.txt'))

        #TODO: MORE PERMUTATIOMS in paths list for meg and just everywhere, for every tool there should be custom wordlist generation.

        #Meg used to fuzz found paths on all other alive subdomains.
        iterable_to_txt(paths['paths'], data['paths'])
        default_scan(axiom, paths['alive'], 'meg', paths["paths"], config['default path'] + 'meg', config['args'].runtime, raw=f'--savestatus {str([x for x in range(100,600) if x is not 404]).replace(" ", "").lstrip("[").rstrip("]")}')
        for file in os.listdir(config['default path'] + '/meg'):
            if os.path.isfile(config['default path'] + '/meg/'+ file):
                data['urls'].update(urlor(file))
                data['paths'].update(pathor(file))

        #Create urls file (not neccesary, can do all it list).
        iterable_to_txt(config['default path'] + 'urls.txt', data['urls'])

        #Create param list and file.
        data['params'].update(paramor(config['default path'] + 'urls.txt'))
        iterable_to_txt(paths['params'], data['params'])

        #TODO: Determine interesting urls etc to pritoritze for scanning in block queues again

        #TODO: Custom Nuclei fuzzing and scanning
        default_scan(axiom, paths['alive'], 'nuclei', '/home/ubuntu/nuclei-templates.txt', config['default path'] + 'nuclei.txt', config['args'].runtime, raw=None)

        #Delete fleet and exit script.
        shutdown(config['args'], axiom)
#----------------------------------------------------------------------------------------------------------------------------------#
if __name__ == "__main__":
    main()
#----------------------------------------------------------------------------------------------------------------------------------#
