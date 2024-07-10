#!/usr/bin/env python3

import ipaddress
import argparse
import requests
import os
import sys
import re
import json
import socket
import subprocess
from tabulate import tabulate
from colorama import Fore, Style
from scrapy.crawler import CrawlerProcess
from tools.scraper.scraper.spiders.spiders import SecretsSpider

class Cloudrec:
    def __init__(self):
        # Define variables
        self.aws_range_path = os.path.expanduser(f"{os.getcwd()}/configs/assets/aws_ip_ranges.json")
        self.configs_path = os.path.expanduser(f"{os.getcwd()}/configs")
        self.tools_path = os.path.expanduser(f"{os.getcwd()}/tools")
        self.azure_range_path = os.path.expanduser(f"{os.getcwd()}/configs/assets/azure_ip_ranges.json")
        self.trusted_resolvers_path = os.path.expanduser(f"{os.getcwd()}/configs/assets/trusted_resolvers.txt")
        self.resolvers_path = os.path.expanduser(f"{os.getcwd()}/configs/assets/resolvers.txt")
        self.subs_big_wordlist = os.path.expanduser(f"{os.getcwd()}/configs/assets/subs_big_wordlist.txt")
        self.subs_wordlist = os.path.expanduser(f"{os.getcwd()}/configs/assets/subs_wordlist.txt")
        # self.pattern = r"^(?:https?://)?(?:[a-zA-Z0-9-]+\.)+?([a-zA-Z0-9-]+)\.(?:[a-zA-Z]+)"
        self.pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:[a-zA-Z]{2,})$'


        # pars variables from crec.cfg file
        config = {}
        with open("configs/cloudrec.cfg", "r") as cfg_file:
            for line in cfg_file:
                if not line.startswith('#') and '=' in line:
                    # Split line by the first occurrence of '='
                    key, value = line.strip().split('=', 1)
                    # Remove trailing comments after the value
                    value = value.split('#', 1)[0].strip()
                    config[key.strip()] = value.strip()

        # Convert specific keys to boolean
        boolean_keys = ['RUNAMASS', 'SUBDNS', 'S3BUCKETS', 'BBRF_CONNECTION', 'RUNSUBFINDER', 'DEEP', 'INSCOPE', 'SUBPASSIVE']
        for key in boolean_keys:
            if key in config:
                config[key] = config[key].lower() == 'true'

        # self.LOGFILE = config.get('LOGFILE', '')
        self.RUNAMASS = config.get('RUNAMASS', '')
        self.SUBDNS = config.get('SUBDNS', '')
        # self.DIFF = config.get('DIFF', '')
        self.AMASS_ENUM_TIMEOUT = config.get('AMASS_ENUM_TIMEOUT', '')
        self.AMASS_CONFIG = config.get('AMASS_CONFIG', '')
        self.RUNSUBFINDER = config.get('RUNSUBFINDER', '')
        self.GITHUB_TOKENS = config.get('GITHUB_TOKENS', '')
        self.DEEP = config.get('DEEP', '')
        self.GITLAB_TOKENS = config.get('GITLAB_TOKENS', '')
        self.INSCOPE = config.get('INSCOPE', '')
        self.SUBPASSIVE = config.get('SUBPASSIVE', '')
        self.S3BUCKETS = config.get('S3BUCKETS', '')

        # PUREDNS CONFIGS
        self.PUREDNS_PUBLIC_LIMIT = config.get('PUREDNS_PUBLIC_LIMIT', '')
        self.PUREDNS_TRUSTED_LIMIT = config.get('PUREDNS_TRUSTED_LIMIT', '')
        self.PUREDNS_WILDCARDTEST_LIMIT = config.get('PUREDNS_WILDCARDTEST_LIMIT', '')
        self.PUREDNS_WILDCARDBATCH_LIMIT = config.get('PUREDNS_WILDCARDBATCH_LIMIT', '')

        self.CTR_LIMIT = config.get('CTR_LIMIT', '')
        self.BBRF_CONNECTION = config.get('BBRF_CONNECTION', '')
        self.BGREEN = config.get('BGREEN', '')
        self.END = config.get('END', '')

        # Create the main parser
        self.parser = argparse.ArgumentParser(description="Enumerate a domain and check if an IP belongs to AWS or AZURE ip pool.")
        self.subparsers = self.parser.add_subparsers(title="commands", dest="command")

        # Setup parser
        self.parser_setup = self.subparsers.add_parser("setup", help="Download tools and configs.")
        
        # AWS parser
        self.parser_aws = self.subparsers.add_parser("aws", help="Run your check against AWS.")
        self.parser_aws.add_argument('domain', help='check a list of IPs')
        self.parser_aws.add_argument('-r','--refresh', help='refresh the AWS IP ranges.', action='store_true')
        
        # AZURE parser
        self.parser_azure = self.subparsers.add_parser("azure", help="Run your check against AZURE.")
        self.parser_azure.add_argument('domain', help='check a list of IPs')
        self.parser_azure.add_argument('-r','--refresh', help='refresh the AZURE IP ranges.', action='store_true')
        
        # ALL parser
        self.parser_all = self.subparsers.add_parser("all", help="Run your check against AWS and AZURE.")
        self.parser_all.add_argument('domain', help='check a list of IPs')
        self.parser_all.add_argument('-r','--refresh', help='refresh the AWS and AZURE IP ranges.', action='store_true')

        # Invoke the appropriate subcommand function based on the parsed arguments
        try:
            args = self.parser.parse_args()
            match = re.match(self.pattern, args.domain)
            if not match:
                print(f"\n{Fore.RED}[x] Invalid domain name! Please make sure that domain name is formatted {Style.RESET_ALL}")
                print("correctly.")
                sys.exit(1)
            
            os.makedirs(f"{os.getcwd()}/targets", exist_ok=True)
            self.target_pattren = re.match(self.pattern, args.domain).group(0)
            self.target_path = f"{os.getcwd()}/targets/{self.target_pattren}"

            if (not os.path.exists(f"{os.getcwd()}/configs")) or (not os.path.exists(f"{os.getcwd()}/tools")):
                print(f"\n{Fore.RED}[x] Run setup subcommand first to download the necessary tools and configs.{Style.RESET_ALL}")
                sys.exit(1)

            os.makedirs(f"{self.target_path}", exist_ok=True)
            os.makedirs(f"{self.target_path}/.tmp", exist_ok=True)

            if args.command == "setup":
                self.setup()
                sys.exit(0)
            elif args.command == "aws":
                self.aws(args)
            elif args.command == "azure":
                self.azure(args)
            elif args.command == "all":
                self.all(args)
            else:
                self.parser.print_help()
        except KeyboardInterrupt:
            print(f"\n{Fore.RED}[!] Operation interrupted. Exiting...{Style.RESET_ALL}")
            sys.exit(0)

    # General config
    def setup(self):
        aws_range_url = "https://ip-ranges.amazonaws.com/ip-ranges.json"
        azure_range_url = 'https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/ServiceTags_Public_20240513.json'
        trusted_resolvers_url = "https://raw.githubusercontent.com/six2dez/resolvers_reconftw/main/resolvers_trusted.txt"
        resolvers_url = "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt"
        subs_big_wordlist = "https://raw.githubusercontent.com/n0kovo/n0kovo_subdomains/main/n0kovo_subdomains_huge.txt"
        subs_wordlist = "https://gist.github.com/six2dez/a307a04a222fab5a57466c51e1569acf/raw"

        # Create configs directory
        os.makedirs(f"{os.getcwd()}/configs", exist_ok=True)

        # Download Azure IP ranges
        try:
            print(f"{Fore.CYAN}[-] Downloading AWS IP ranges ...{Style.RESET_ALL}")
            response = requests.get(aws_range_url)
            if response.status_code == 200:
                with open(self.aws_range_path, 'wb') as file:
                    file.write(response.content)
                print(f"    {Fore.GREEN}[+] The AWS IP ranges are downloaded and saved to: [{self.aws_range_path}]{Style.RESET_ALL}")
            else:
                print(f"    {Fore.RED}[x] Unable to download AWS IP ranges. Status code: {response.status_code}{Style.RESET_ALL}")
        except Exception as e:
            print(f"    {Fore.RED}[x] An error occurred while downloading AWS IP ranges: {e}{Style.RESET_ALL}")
            sys.exit(1)

        # Download Azure IP ranges
        try:
            print(f"{Fore.CYAN}[-] Downloading AWS IP ranges ...{Style.RESET_ALL}")
            response = requests.get(azure_range_url)
            if response.status_code == 200:
                with open(self.azure_range_path, 'wb') as file:
                    file.write(response.content)
                print(f"    {Fore.GREEN}[+] The AZURE IP ranges are downloaded and saved to: [{self.azure_range_path}]{Style.RESET_ALL}")
            else:
                print(f"    {Fore.RED}[x] Unable to download AZURE IP ranges. Status code: {response.status_code}{Style.RESET_ALL}")
        except Exception as e:
            print(f"    {Fore.RED}[x] An error occurred while downloading AZURE IP ranges: {e}{Style.RESET_ALL}") 
            sys.exit(1) 

        # Download Trusted IP Resolvers
        try:
            print(f"{Fore.CYAN}[-] Downloading trusted IP resolvers ...{Style.RESET_ALL}")
            response = requests.get(trusted_resolvers_url)
            if response.status_code == 200:
                with open(self.trusted_resolvers_path, 'wb') as file:
                    file.write(response.content)
                print(f"    {Fore.GREEN}[+] The trusted IP resolvers downloaded and saved to: [{self.trusted_resolvers_path}]{Style.RESET_ALL}")
            else:
                print(f"    {Fore.RED}[x] Unable to download trusted IP resolvers. Status code: {response.status_code}{Style.RESET_ALL}")
        except Exception as e:
            print(f"    {Fore.RED}[x] An error occurred while downloading trusted IP resolvers: {e}{Style.RESET_ALL}")
            sys.exit(1)
        
        # Download IP Resolvers
        try:
            print(f"{Fore.CYAN}[-] Downloading IP resolvers ...{Style.RESET_ALL}")
            response = requests.get(resolvers_url)
            if response.status_code == 200:
                with open(self.resolvers_path, 'wb') as file:
                    file.write(response.content)
                print(f"{Fore.GREEN}    [+] The IP resolvers downloaded and saved to: [{self.resolvers_path}]{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}    [x] Unable to download IP resolvers. Status code: {response.status_code}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}    [x] An error occurred while downloading IP resolvers: {e}{Style.RESET_ALL}")
            sys.exit(1)

        # Download the big subdomains wordlist
        try:
            print(f"{Fore.CYAN}[-] Downloading subdomains big wordlist ...{Style.RESET_ALL}")
            response = requests.get(subs_big_wordlist)
            if response.status_code == 200:
                with open(self.subs_big_wordlist, 'wb') as file:
                    file.write(response.content)
                print(f"{Fore.GREEN}    [+] The subdomains big wordlist downloaded and saved to: [{self.subs_big_wordlist}]{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}    [x] Unable to download subdomains big wordlist. Status code: {response.status_code}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}    [x] An error occurred while downloading subdomains big wordlist{Style.RESET_ALL}")
            sys.exit(1)

        # Download the subdomains wordlist
        try:
            print(f"{Fore.CYAN}[-] Downloading subdomains wordlist ...{Style.RESET_ALL}")
            response = requests.get(subs_wordlist)
            if response.status_code == 200:
                with open(self.subs_wordlist, 'wb') as file:
                    file.write(response.content)
                print(f"{Fore.GREEN}    [+] The subdomains wordlist downloaded and saved to: [{self.subs_wordlist}]{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}    [x] Unable to download subdomains wordlist. Status code: {response.status_code}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}    [x] An error occurred while downloading subdomains wordlist{Style.RESET_ALL}")
            sys.exit(1)

    def is_ip_in_aws_ranges(self, ip_address):
        with open(self.aws_range_path, 'r') as file:
                aws_ranges = json.load(file)['prefixes']

        ip = ipaddress.ip_address(ip_address)
        for entry in aws_ranges:
            aws_ip_range = ipaddress.ip_network(entry['ip_prefix'])
            if ip in aws_ip_range:
                return entry['ip_prefix'], entry['region'], entry['service']
        return None, None, None

    def is_ip_in_azure_ranges(self, ip_address):
        with open(self.azure_range_path, 'r') as file:
            azure_ranges = json.load(file)['values']

        ip = ipaddress.ip_address(ip_address)
        for entry in azure_ranges:
            for s_range in entry['properties']['addressPrefixes']:
                azure_ip_range = ipaddress.ip_network(s_range)
                if ip in azure_ip_range:
                    return ip, entry['properties']['region'], entry['properties']['systemService']
        return None, None, None

    def get_ip_address(self, domain):
        try:
            ip_address = socket.gethostbyname(domain)
            return ip_address
        except socket.gaierror:
            return None

    def load_ips(self):
        ips = []
        with open(f'{self.target_path}/resolved_subdomains.txt', 'r') as file:
            lines = file.readlines()

        for line in lines:
            subdomain, ip = line.strip().split(':')
            ips.append({'ip': ip, 'subdomain': subdomain})

        return ips

    def remove_duplicates(self, file_path):
        # Read the lines from the file and store unique lines in a set
        unique_lines = set()
        with open(file_path, 'r') as file:
            for line in file:
                unique_lines.add(line.strip())

        # Write unique lines back to the file
        with open(file_path, 'w') as file:
            for line in unique_lines:
                file.write(line + '\n')

    def resolve_subdomain(self):
        if not os.path.exists(f"{self.target_path}/resolved_subdomains.txt"):
            print(f"{Fore.CYAN}[-] Resolving subdomains ...{Style.RESET_ALL}")
            print(f"{Fore.GREEN}    [+] Resolved subdomains:{Style.RESET_ALL}")
            with open(f"{self.target_path}/subdomains.txt", 'r') as infile, open(f"{self.target_path}/resolved_subdomains.txt", 'w') as outfile:
                for line in infile:
                    subdomain = line.strip()
                    ip_address = self.get_ip_address(subdomain)
                    if ip_address:
                        print(f"      - {subdomain}:{ip_address}")   
                        outfile.write(f"{subdomain}:{ip_address}\n")
        else:
            print(f"{Fore.RED}[!] resolving is already processed, to force executing resolving subdomains, delete: {Fore.YELLOW}{self.target_path}/resolved_subdomains.txt{Style.RESET_ALL}")

    def live_subdomains(self):
        if os.path.exists(f"{self.target_path}/resolved_subdomains.txt"):
            if not os.path.exists(f"{self.target_path}/live_subdomains.txt"):
                print(f"{Fore.CYAN}[-] Checking for live subdomains ...{Style.RESET_ALL}")

                httpx = subprocess.Popen(f"cat {self.target_path}/subdomains.txt | httpx -sc | grep 200 | cut -d' ' -f1", shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)

                output, _ = httpx.communicate()

                with open(f"{self.target_path}/live_subdomains.txt", "w") as file:
                    file.write(output.decode("utf-8"))
                
                print(f"{Fore.GREEN}    [+] Founded live subdomains:{Style.RESET_ALL}")
                with open(f"{self.target_path}/live_subdomains.txt", 'r') as file:
                    for line in file:
                        print(f"      - {line.strip()}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[!] live domains is already processed, to force executing live subdomains, delete: {Fore.YELLOW}{self.target_path}/live_subdomains.txt{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}    [x] no subdomains founded to enumerate{Style.RESET_ALL}")

    # General recon
    def sub_passive(self, domain):
        if not os.path.exists(f"{self.target_path}/.tmp/passive_subs.txt"):
            if self.RUNAMASS:
                print(f"{Fore.CYAN}[-] Running amass for subdomains enummeration ...{Style.RESET_ALL}")
                amass = subprocess.Popen(f"timeout -k 1m {str(self.AMASS_ENUM_TIMEOUT)} amass enum -passive -d {domain} -timeout {str(self.AMASS_ENUM_TIMEOUT)}", shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.PIPE)

                processed_output = subprocess.Popen(f"cut -d' ' -f1 | grep {self.target_pattren}", shell=True, stdin=amass.stdout, stderr=subprocess.DEVNULL, stdout=subprocess.PIPE)
                
                output, _ = processed_output.communicate()
                with open(f"{self.target_path}/.tmp/amass_psub.txt", "w") as file:
                    file.write(output.decode("utf-8"))

            if self.RUNSUBFINDER:
                print(f"{Fore.CYAN}[-] Running subfinder for subdomains enummeration ...{Style.RESET_ALL}")
                subprocess.run(f"subfinder -all -d {domain} -silent -o {self.target_path}/.tmp/subfinder_psub.txt", shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

            if os.path.exists(self.GITHUB_TOKENS):
                print(f"{Fore.CYAN}[-] Running github-subdomains for subdomains enummeration (GITHUB_TOKENS) ...{Style.RESET_ALL}")
                if self.DEEP:
                    subprocess.run(f"github-subdomains -d {domain} -t {self.GITHUB_TOKENS} -o {self.target_path}/.tmp/github_subdomains_psub.txt", shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.PIPE)
                else:
                    subprocess.run(f"github-subdomains -d {domain} -k -q -t {self.GITHUB_TOKENS} -o {self.target_path}/.tmp/github_subdomains_psub.txt", shell=True,stderr=subprocess.DEVNULL, stdout=subprocess.PIPE)

            if os.path.exists(self.GITLAB_TOKENS):
                print(f"{Fore.CYAN}[-] Running github-subdomains for subdomains enummeration (GITLAB_TOKENS) ...{Style.RESET_ALL}")
                subprocess.run(f"gitlab-subdomains -d {domain} -t {self.GITLAB_TOKENS}", shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.PIPE)

            for root, _, files in os.walk(f"{self.target_path}/.tmp"):
                for file in files:
                    if file.endswith("_psub.txt"):
                        with open(os.path.join(root, file), "r") as f:
                            lines = f.readlines()
                            with open(f"{self.target_path}/.tmp/passive_subs.txt", "a") as output_file:
                                for line in lines:
                                    if line.strip():
                                        output_file.write(line.strip() + "\n")

            # Add founded subdomains to the total subdomains
            with open(f"{self.target_path}/.tmp/passive_subs.txt", 'r') as infile, open(f"{self.target_path}/subdomains.txt", 'w') as outfile:
                for line in infile:
                    subdomain = line.strip()
                    outfile.write(f"{subdomain}\n")
            
            # Remove duplicated subdomains
            self.remove_duplicates(f"{self.target_path}/subdomains.txt")

            # Delete tmp files
            if os.path.exists(f"{self.target_path}/.tmp/github_subdomains_psub.txt"):
                os.remove(f"{self.target_path}/.tmp/github_subdomains_psub.txt")
            if os.path.exists(f"{self.target_path}/.tmp/subfinder_psub.txt"):
                os.remove(f"{self.target_path}/.tmp/subfinder_psub.txt")
            if os.path.exists(f"{self.target_path}/.tmp/amass_psub.txt"):
                os.remove(f"{self.target_path}/.tmp/amass_psub.txt")
        else:
            print(f"{Fore.RED}[!] passive enumeration is already processed, to force executing passive enumeration, delete: {Fore.YELLOW}{self.target_path}/.tmp/passive_subs.txt{Style.RESET_ALL}")

    def sub_crt(self, domain):
        if not os.path.exists(f"{self.target_path}/.tmp/crt_subs.txt"):
            print(f"{Fore.CYAN}[-] Running crt for subdomains enummeration ...{Style.RESET_ALL}")
            
            crt_process = subprocess.Popen(f"crt -s -json -l {str(self.CTR_LIMIT)} {domain}", shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.PIPE)
            crt_output, crt_error = crt_process.communicate()

            crt_data = json.loads(crt_output.decode('utf-8'))
            subdomains = [item['subdomain'] for item in crt_data]

            # Remove prefix '*.' from subdomains
            subdomains = [subdomain[2:] if subdomain.startswith('*.') else subdomain for subdomain in subdomains]

            # Write subdomains to .tmp/crtsh_subs_tmp.txt
            with open(f"{self.target_path}/.tmp/crt_subs_tmp.txt", 'w') as crtsh_subs_tmp:
                crtsh_subs_tmp.write('\n'.join(subdomains))

            # Count new subs and write to .tmp/crtsh_subs.txt
            with open(f"{self.target_path}/.tmp/crt_subs_tmp.txt", 'r') as crtsh_subs_tmp:
                subdomains_no_prefix = [subdomain[2:] if subdomain.startswith('*.') else subdomain for subdomain in crtsh_subs_tmp.readlines()]
                subdomains_no_blank = [subdomain.strip() for subdomain in subdomains_no_prefix if subdomain.strip()]
                unique_subdomains = set(subdomains_no_blank)

                with open(f"{self.target_path}/.tmp/crt_subs.txt", 'w') as crtsh_subs:
                    crtsh_subs.write('\n'.join(unique_subdomains))

            with open(f"{self.target_path}/.tmp/crt_subs.txt", 'r') as infile, open(f"{self.target_path}/subdomains.txt", 'a') as outfile:
                for line in infile:
                    subdomain = line.strip()
                    outfile.write(f"{subdomain}\n")

            # Remove duplicated subdomains
            self.remove_duplicates(f"{self.target_path}/subdomains.txt")

            # Deleting tmp files
            if os.path.exists(f"{self.target_path}/.tmp/crt_subs_tmp.txt"):
                os.remove(f"{self.target_path}/.tmp/crt_subs_tmp.txt")
        else:
            print(f"{Fore.RED}[!] crt enumeration is already processed, to force executing crt enumeration, delete: {Fore.YELLOW}{self.target_path}/.tmp/crt_subs.txt{Style.RESET_ALL}")

    def sub_dns(self, domain):
        if not os.path.exists(f"{self.target_path}/.tmp/dns_subs.txt"):
            print(f"{Fore.CYAN}[-] Running dns subdomains enummeration ...{Style.RESET_ALL}")

            subprocess.run(f"cat {self.target_path}/subdomains.txt | dnsx -r {self.trusted_resolvers_path} -a -aaaa -cname -ns -ptr -mx -soa -silent -retry 3 -json -o {self.target_path}/.tmp/subdomains_dnsregs.json 2>/dev/null", shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.PIPE)

            subprocess.run(f"cat {self.target_path}/.tmp/subdomains_dnsregs.json | jq -r 'try .a[], try .aaaa[], try .cname[], try .ns[], try .ptr[], try .mx[], try .soa[]' 2>/dev/null | grep \".{domain}$\" | grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]"+"{1,}(\/.*)?$'"+f" | anew -q {self.target_path}/.tmp/dns_subs.txt", shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.PIPE)

            subprocess.run(f"cat {self.target_path}/.tmp/subdomains_dnsregs.json | jq -r 'try .a[]' | sort -u | hakip2host | cut -d' ' -f 3 | unfurl -u domains | sed -e 's/*\.//' -e 's/\.$//' -e '/\./!d' | grep \".{domain}\" | grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]"+"{1,}(\/.*)?$'"+f" | anew -q {self.target_path}/.tmp/dns_subs.txt", shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.PIPE)

            # get_subdomains_ips = subprocess.run(f"cat {self.target_path}/.tmp/subdomains_dnsregs.json | jq -r 'try \"\(.host) - \(.a[])\"' 2>/dev/null | sort -u -k2 | anew -q {self.target_path}/.tmp/dns_subs_ips.txt", shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.PIPE)

            # Add founded subdomains to the total subdomains
            with open(f"{self.target_path}/.tmp/dns_subs.txt", "r") as infile, open(f"{self.target_path}/subdomains.txt", "a") as outfile:
                for line in infile:
                    subdomain = line.strip()
                    outfile.write(f"{subdomain}\n")

            # Remove duplicated subdomains
            self.remove_duplicates(f"{self.target_path}/subdomains.txt")

            # Deleting tmp files
            if os.path.exists(f"{self.target_path}/.tmp/subdomains_dnsregs.json"):
                os.remove(f"{self.target_path}/.tmp/subdomains_dnsregs.json")
        else:
            print(f"{Fore.RED}[!] dns enumeration is already processed, to force executing dns enumeration, delete: {Fore.YELLOW}{self.target_path}/.tmp/dns_subs.txt{Style.RESET_ALL}")

    def sub_brute(self, domain):
        if not os.path.exists(f"{self.target_path}/.tmp/brute_subs.txt"):
            print(f"{Fore.CYAN}[-] Brute forcing subdomains ...{Style.RESET_ALL}")

            subprocess.run(f"puredns bruteforce {self.subs_big_wordlist} {domain} -w {self.target_path}/.tmp/brute_subs.txt -r {self.resolvers_path} --resolvers-trusted {self.trusted_resolvers_path} -l {self.PUREDNS_PUBLIC_LIMIT} --rate-limit-trusted {self.PUREDNS_TRUSTED_LIMIT} --wildcard-tests {self.PUREDNS_WILDCARDTEST_LIMIT} --wildcard-batch {self.PUREDNS_WILDCARDBATCH_LIMIT} 2 >/dev/null", shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.PIPE)

            # Add founded subdomains to the total subdomains
            with open(f"{self.target_path}/.tmp/brute_subs.txt", "r") as infile, open(f"{self.target_path}/subdomains.txt", "a") as outfile:
                for line in infile:
                    subdomain = line.strip()
                    outfile.write(f"{subdomain}\n")

            # Remove duplicated subdomains
            self.remove_duplicates(f"{self.target_path}/subdomains.txt")
        else:
            print(f"{Fore.RED}[!] subdomain brute forcing is already processed, to force executing dns enumeration, delete: {Fore.YELLOW}{self.target_path}/.tmp/dns_subs.txt{Style.RESET_ALL}")

    def scrape_domain(self):
        if not os.path.exists(f"{self.target_path}/js_files.txt"):
            print(f"{Fore.CYAN}[-] Scraping for js files ...{Style.RESET_ALL}")
            with open(f"{self.target_path}/live_subdomains.txt", "r") as subdomains:
                for subdomain in subdomains:
                    print(f"{Fore.GREEN}    [+] Scraping {subdomain.strip()} ...{Style.RESET_ALL}")
                    subprocess.run(f"gospider -s {subdomain.strip()} -a -w -r --sitemap --robots | grep '{self.target_pattren}' | grep -aEo 'https?://[^ ]+' | sed 's/]$//' | sort -u| grep -aEi "+'"\.(js)"'+f" | httpx -sc | grep 200 | cut -d' ' -f1 | anew -q {self.target_path}/js_files.txt", shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.PIPE)

                    subprocess.run(f"echo {subdomain.strip()} | hakrawler -subs | grep '{self.target_pattren}' | grep -aEo 'https?://[^ ]+' | sed 's/]$//' | sort -u| grep -aEi "+'"\.(js)"'+f" | httpx -sc | grep 200 | cut -d' ' -f1 | anew -q {self.target_path}/js_files.txt", shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.PIPE)

                    subprocess.run(f"echo {subdomain.strip()} | waybackurls | grep '{self.target_pattren}' | grep -aEo 'https?://[^ ]+' | sed 's/]$//' | sort -u| grep -aEi "+'"\.(js)"'+f" | httpx -sc | grep 200 | cut -d' ' -f1 | anew -q {self.target_path}/js_files.txt", shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.PIPE)
        else:
            print(f"{Fore.RED}[!] scrapping domains is already processed, to force executing scrapping subdomains, delete: {Fore.YELLOW}{self.target_path}/js_files.txt{Style.RESET_ALL}")

        # subprocess.run(f"nuclei -l {self.target_path}/js_files.txt -t ~/.local/nuclei-templates/exposures/ | grep 200 | cut -d' ' -f1 | anew -q {self.target_path}/js_files.txt", shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.PIPE)
        
        # # Suppress stdout to silence Scrapy's default output
        # sys.stdout = open('/dev/null', 'w')
        # sys.stderr = open('/dev/null', 'w')

        # process = CrawlerProcess(settings={
        # 'USER_AGENT': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        # # Add any other settings you need
        # })

        # process.crawl(SecretsSpider, js_files_path=f"{self.target_path}/js_files.txt")
        # process.start()

        # # Re-enable stdout
        # sys.stdout = sys.__stdout__
        # sys.stderr = sys.__stderr__

    # AWS recon
    def s3_wordlist(self):
        with open(f"{self.target_path}/subdomains.txt", 'r') as infile:
            subdomains = set()
            for line in infile:
                # Split each line by dots and take all parts except the last one
                parts = line.strip().split('.')
                if len(parts) > 2:  # Check if there are nested subdomains
                    subdomain = '.'.join(parts)
                    subdomains.add(subdomain)
                    subdomains.add(subdomain.replace('.', '-'))
                    parts = parts[:-1]
                    subdomain = '.'.join(parts)
                    subdomains.add(subdomain)
                    subdomains.add(subdomain.replace('.', '-'))  # Add subdomain with dashes

        with open(f"{self.target_path}/s3_wordlist.txt", 'w') as outfile:
            for subdomain in subdomains:
                outfile.write(subdomain + '\n')

    def aws_assets(self, name, domain):
        self.s3_wordlist()

        # S3Scanner
        if os.path.exists(f"{self.target_path}/subdomains.txt"):
            print(f"{Fore.CYAN}[-] Searching for buckets by brute force ...{Style.RESET_ALL}")
            subprocess.run(f"s3scanner -threads 100 -enumerate -bucket-file {self.target_path}/s3_wordlist.txt | anew -q {self.target_path}/.tmp/s3buckets.txt", shell=True, stdout=subprocess.PIPE)

            subprocess.run(f"cat {self.target_path}/.tmp/s3buckets.txt 2>/dev/null | grep -iv 'not_exist' | grep -iv 'invalid' | grep -iv 'error' | grep -iv 'Warning:' | grep -iv 'invalid_name' | grep -iv '^http' | awk 'NF' | cut -d'\"' -f2 | anew {self.target_path}/s3buckets.txt", shell=True, capture_output=True, text=True).stdout.strip()

            print(f"{Fore.GREEN}    [+] S3 buckets founded:{Style.RESET_ALL}")
            with open(f"{self.target_path}/s3buckets.txt", 'r') as buckets:
                for bucket in buckets:
                    print(f"      - {bucket.strip()}")

            # Cloudenum
            print(f"{Fore.CYAN}[-] Searching for aws assets ...{Style.RESET_ALL}")
            subprocess.run(f"python3 tools/cloud_enum/cloud_enum.py -qs -k {name} -k {domain} --disable-azure --disable-gcp -l {self.target_path}/.tmp/output_cloud.txt 2>/dev/null", shell=True, stdout=subprocess.PIPE)

            subprocess.run(f"cat {self.target_path}/.tmp/output_cloud.txt 2>/dev/null | sed '/^#/d' | sed '/^$/d' | anew {self.target_path}/cloud_assets.txt", shell=True, capture_output=True, text=True).stdout.strip()

            print(f"{Fore.GREEN}    [+] Cloud assets found{Style.RESET_ALL}")
            with open(f"{self.target_path}/cloud_assets.txt", 'r') as assets:
                for asset in assets:
                    print(f"      - {asset.strip()}")

            # Delete tmp files
            if os.path.exists(f"{self.target_path}/.tmp/output_cloud.txt"):
                os.remove(f"{self.target_path}/.tmp/output_cloud.txt")
        else:
            print(f"{Fore.RED}    [!] no subdomains founded to enumerate{Style.RESET_ALL}")
    
    # Azure recon
    def az_assets(self, name, domain):
        if not os.path.exists(f"{self.target_path}/az_assets.txt"):
            print(f"{Fore.CYAN}[-] Searching for azure assets ...{Style.RESET_ALL}")
            # subprocess.run(f'pwsh -Command "Import-Module ./tools/MicroBurst/MicroBurst.psm1; Invoke-EnumerateAzureBlobs -Base {name}" >> {self.target_path}/.tmp/az_blobs.txt', shell=True, stdout=subprocess.PIPE)

            # Cloudenum
            subprocess.run(f"python3 tools/cloud_enum/cloud_enum.py -qs -k {name} -k {domain} --disable-gcp --disable-aws -l {self.target_path}/.tmp/enum_output.txt 2>/dev/null", shell=True, stdout=subprocess.PIPE)

            subprocess.run(f"cat {self.target_path}/.tmp/enum_output.txt 2>/dev/null | sed '/^#/d' | sed '/^$/d' | anew {self.target_path}/az_assets.txt", shell=True, capture_output=True, text=True).stdout.strip()

            with open(f"{self.target_path}/az_assets.txt", 'r') as assets:
                if os.path.getsize(f"{self.target_path}/az_assets.txt") == 0:
                    print(f"{Fore.BLACK}    [!] No azure assets found{Style.RESET_ALL}")
                else:
                    print(f"{Fore.GREEN}    [+] Subdomains and tenants found:{Style.RESET_ALL}")
                    for asset in assets:
                        print(f"      - {asset.strip()}")

            # Delete tmp files
            if os.path.exists(f"{self.target_path}/.tmp/az_blobs.txt"):
                os.remove(f"{self.target_path}/.tmp/az_blobs.txt")
            if os.path.exists(f"{self.target_path}/.tmp/enum_output.txt"):
                os.remove(f"{self.target_path}/.tmp/enum_output.txt")
        else:
            print(f"{Fore.RED}[!] az assets is already processed, to force executing scrapping subdomains, delete: {Fore.YELLOW}{self.target_path}/az_assets.txt{Style.RESET_ALL}")

    def az_infos(self, name, domain):
        if not os.path.exists(f"{self.target_path}/az_infos.txt"):
            print(f"{Fore.CYAN}[-] Searching for target azure subdoamins and tenants ...{Style.RESET_ALL}")
            # subprocess.run(f'pwsh -Command "Import-Module ./tools/MicroBurst/MicroBurst.psm1; Invoke-EnumerateAzureSubDomains -Base {name} -Verbose" >> {self.target_path}/.tmp/az_burst_domains.txt', shell=True, stdout=subprocess.PIPE)

            # subprocess.run(f'pwsh -Command "Import-Module AADInternals; Get-AADIntTenantDomains -Domain {domain}" >> {self.target_path}/.tmp/az_adint_domains.txt', shell=True, stdout=subprocess.PIPE)

            subprocess.run(f'pwsh -Command "Import-Module AADInternals; Invoke-AADIntReconAsOutsider -Domain "{domain}" | Format-Table" | grep -iv "AADInternals" | grep -iv "|" | tail -n +8 >> {self.target_path}/.tmp/az_tenats.txt', shell=True, stdout=subprocess.PIPE)

            subprocess.run(f"cat {self.target_path}/.tmp/az_tenats.txt 2>/dev/null | sed '/^#/d' | sed '/^$/d' | anew {self.target_path}/az_infos.txt", shell=True, capture_output=True, text=True).stdout.strip()

            with open(f"{self.target_path}/az_infos.txt", 'r') as assets:
                if os.path.getsize(f"{self.target_path}/az_infos.txt") == 0:
                    print(f"{Fore.YELLOW}    [!] No subdomains or tenants found{Style.RESET_ALL}")
                else:
                    print(f"{Fore.GREEN}    [+] Subdomains and tenants found:{Style.RESET_ALL}")
                    for asset in assets:
                        print(f"        {asset.strip()}")

            # Delete tmp files
            if os.path.exists(f"{self.target_path}/.tmp/az_burst_domains.txt"):
                os.remove(f"{self.target_path}/.tmp/az_burst_domains.txt")
            if os.path.exists(f"{self.target_path}/.tmp/az_adint_domains.txt"):
                os.remove(f"{self.target_path}/.tmp/az_adint_domains.txt")
            if os.path.exists(f"{self.target_path}/.tmp/az_tenats.txt"):
                os.remove(f"{self.target_path}/.tmp/az_tenats.txt")
        else:
            print(f"{Fore.RED}[!] az infos is already processed, to force executing az infos, delete: {Fore.YELLOW}{self.target_path}/az_infos.txt{Style.RESET_ALL}")

    def aws(self, args, dubbeled=False):
        domain = self.target_pattren
        name = domain.split(".")[-2]
        belonged_ips = []

        if not dubbeled:
            if args.refresh:
                self.setup()

            self.sub_passive(domain)
            self.sub_crt(domain)
            self.sub_dns(domain)
            # self.sub_brute(domain)
            self.resolve_subdomain()
            self.live_subdomains()
            self.scrape_domain()

        self.aws_assets(name, domain)

        ip_list = self.load_ips()
        print(f"{Fore.CYAN}[-] Searching for IPs belongs to cloud platforms ...{Style.RESET_ALL}")
        for item in ip_list:
            if item['ip'] != "none":
                ip_prefix, region, service = self.is_ip_in_aws_ranges(item['ip'])
                if ip_prefix is not None:
                    belonged_ips.append([item['subdomain'], item['ip'], region, service])
        
        # Print the formatted table
        headers = ["Subdomain", "IP", "Region", "Service"]
        print(f"    {Fore.GREEN}[+] IPs belong to AWS:{Style.RESET_ALL}")
        print(f"{tabulate(belonged_ips, headers=headers, tablefmt='psql')}")

    def azure(self, args, dubbeled=False):
        domain = self.target_pattren
        name = domain.split(".")[-2]
        belonged_ips = []

        if not dubbeled:
            if args.refresh:
                self.setup()

            self.sub_passive(domain)
            self.sub_crt(domain)
            self.sub_dns(domain)
            # self.sub_brute(domain)
            self.resolve_subdomain()
            self.live_subdomains()
            self.scrape_domain()
        
        self.az_assets(name, domain)
        self.az_infos(name, domain)
        
        ip_list = self.load_ips()
        print(f"{Fore.CYAN}[-] Looking for IPs belongs to AZURE ...{Style.RESET_ALL}")
        for item in ip_list:
            if item['ip'] != "none":
                ip_prefix, region, service = self.is_ip_in_azure_ranges(item['ip'])
                if ip_prefix is not None:
                    belonged_ips.append([item['subdomain'], item['ip'], region, service])
        
        # Print the formatted table
        headers = ["Subdomain", "IP", "Region", "Service"]
        print(f"{Fore.GREEN}[+] IPs belong to AZURE:{Style.RESET_ALL}")
        print(tabulate(belonged_ips, headers=headers, tablefmt="psql"))

    def all(self, args):
        self.aws(args)
        self.azure(args, True)

cloudrec = Cloudrec()