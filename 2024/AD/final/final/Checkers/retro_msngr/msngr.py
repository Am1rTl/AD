import requests
import string
import time
from random import choice, randint
from requests.packages.urllib3.exceptions import InsecureRequestWarning


requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


timeout = 7

SERVICE_STATE_UP 		= 'UP'  		# everything is ok
SERVICE_STATE_DOWN 		= 'DOWN'  		# no tcp connect
SERVICE_STATE_MUMBLE 	= 'MUMBLE'  	# something wrong
SERVICE_STATE_CORRUPTED = 'CORRUPT'		# no flag

def getRandomUA():
	uas = [
		'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36',
		'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.121 Safari/537.36',
		'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 1.1.4322)',
		'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36',
		'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36',
		'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_5) AppleWebKit/605.1.15 (KHTML, like Gecko)',
		'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/605.1.15 (KHTML, like Gecko)',
		'Mozilla/5.0 (iPhone; CPU iPhone OS 13_1_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.1 Mobile/15E148 Safari/604.1',
		'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36'
	]
	return uas[randint(0,len(uas)-1)]

def getRandomExploit():
	expls = [
		'\' union select 1,2,message from users where message like "%=%" -- -',
		'\' or sleep(10) -- -',
		'<%= for a in users: print(a.message) %>',
		'%p%p%p%p%p%p%p%p%s\n\n',
		'testtest" select msg from user_table; #'
	]
	return expls[randint(0,len(expls)-1)]


def randomString(length):
	chars = string.ascii_letters + string.digits
	return ''.join(choice(chars) for _ in range(length))

def check_functionality(ip):
	url = f"https://{ip}:7878/"
	try:
		requests.get(url, verify=False, timeout=timeout, headers={'User-Agent' : getRandomUA()})
	except Exception as e:
		return SERVICE_STATE_DOWN,'Service unreachable',str(e)

	user = randomString(14)
	pasw = randomString(12)

	# LOGIN CHECK
	try:
		r = requests.post(url+'login.m', data=f"{user}\x00{pasw}\x00", verify=False, timeout=timeout, headers={'User-Agent' : getRandomUA()})
		if r.status_code != 200:
			return SERVICE_STATE_MUMBLE,'Module login.m does not work',f'Status code: {r.status_code}'
		if r.text.strip() != "BAD CRED":
			return SERVICE_STATE_MUMBLE,'Module login.m does not work',f'Intead of BAD CRED we got {r.text.strip()} \nUsr: {user} \nPasw: {pasw}'
	except Exception as e:
		return SERVICE_STATE_MUMBLE,'Module login.m does not work', str(e)

	# ADMIN CHECK
	try:
		r = requests.post(url+'admin.m', data=f"{user}\x00{pasw}\x00", verify=False, timeout=timeout, headers={'User-Agent' : getRandomUA()})
		if r.status_code != 200:
			return SERVICE_STATE_MUMBLE,'Module admin.m does not work',f'Status code: {r.status_code}'
		if r.text.strip() != "BAD CRED":
			return SERVICE_STATE_MUMBLE,'Module admin.m does not work',f'Intead of BAD CRED we got {r.text.strip()}'
	except Exception as e:
		return SERVICE_STATE_MUMBLE,'Module admin.m does not work',str(e)


	# REG USER CHECK

	usr1 = randomString(14)
	psw1 = randomString(12)
	usr2 = randomString(14)
	psw2 = randomString(12)

	try:
		r = requests.post(url+"register.m", data=f"{usr1}\x00{psw1}\x00", verify=False, timeout=timeout, headers={'User-Agent' : getRandomUA()})
		if r.status_code != 200:
			return SERVICE_STATE_MUMBLE,'Module register.m cant register user',f'Status code: {r.status_code}'

		if r.text.strip() != "USR REGISTERED":
			return SERVICE_STATE_MUMBLE,'Module register.m cant register user',f'Instead of USR REGISTERED we got {r.text.strip()}  \nUsr: {usr1} \nPasw: {psw1}'

		r = requests.post(url+"register.m", data=f"{usr2}\x00{psw2}\x00", verify=False, timeout=timeout, headers={'User-Agent' : getRandomUA()})
		if r.status_code != 200:
			return SERVICE_STATE_MUMBLE,'Module register.m cant register user',f'Status code: {r.status_code}'

		if r.text.strip() != "USR REGISTERED":
			return SERVICE_STATE_MUMBLE,'Module register.m cant register user',f'Instead of USR REGISTERED we got {r.text.strip()}  \nUsr: {usr2} \nPasw: {psw2}'
	except Exception as e:
		return SERVICE_STATE_MUMBLE,'Module register.m cant register user',str(e)


	# SENDMSG CHECK
	mssg = randomString(5)+' '+getRandomExploit()+' '+randomString(5)

	try:
		r = requests.post(url+'sendmsg.m', data=f"{usr1}\x00{psw1}\x00{usr2}\x00{mssg}\x00", verify=False, timeout=timeout, headers={'User-Agent' : getRandomUA()})
		if r.status_code != 200:
			return SERVICE_STATE_MUMBLE,'Module sendmsg.m does not work',f'Status code: {r.status_code}'
		if r.text.strip() != "MSG SENT":
			return SERVICE_STATE_MUMBLE,'Module sendmsg.m does not work',f'Instead of MSG SENT we got {r.text.strip()} \nMsg: {mssg}'
	except Exception as e:
		return SERVICE_STATE_MUMBLE,'Module sendmsg.m does not work',str(e)

	# GETMSG CHECK
	try:
		r = requests.post(url+'getmsg.m', data=f"{usr2}\x00{psw2}\x00{usr1}\x00", verify=False, timeout=timeout, headers={'User-Agent' : getRandomUA()})
		if r.status_code != 200:
			return SERVICE_STATE_MUMBLE,'Module getmsg.m does not work',f'Status code: {r.status_code}'
		if not mssg in r.text.strip():
			return SERVICE_STATE_MUMBLE,'Module getmsg.m does not work',f'No message, got {r.text.strip()} instead of {mssg}'
	except Exception as e:
		return SERVICE_STATE_MUMBLE,'Module getmsg.m does not work',str(e)

	return SERVICE_STATE_UP,'MSNGR up',''


def push_flag(ip, flag):
	url = f"https://{ip}:7878/"

	users = ['Alice', 'Bob', 'Katie', 'Jack', 'Britney', 'Carl', 'Emma', 'Dan', 'Leyla', 'Erick']
	username = users[randint(0,len(users)-1)]+str(int(time.time()))
	password = randomString(18)


	try:
		r = requests.post(url+"register.m", data=f"{username}\x00{password}\x00", verify=False, timeout=timeout, headers={'User-Agent' : getRandomUA()})
		if r.status_code != 200:
			return SERVICE_STATE_MUMBLE,'Module register.m cant register user',f'Status code: {r.status_code}'
		if r.text.strip() != "USR REGISTERED":
			return SERVICE_STATE_MUMBLE,'Module register.m cant register user',f'Instead of USR REGISTERED we got {r.text.strip()} \nUsr: {username} \nPsw: {password}'
	except Exception as e:
		return SERVICE_STATE_MUMBLE,'Module register.m cant register user',str(e)

	try:
		r = requests.post(url+"sendmsg.m", data=f"{username}\x00{password}\x00admin\x00{flag}\x00", verify=False, timeout=timeout, headers={'User-Agent' : getRandomUA()})
		if r.status_code != 200:
			return SERVICE_STATE_MUMBLE,'Module sendmsg.m cant receive flag',f'Status code: {r.status_code}'
		if r.text.strip() != "MSG SENT":
			return SERVICE_STATE_MUMBLE,'Module sendmsg.m cant receive flag',f'Instread of MSG SENT we got {r.text.strip()} \nUsr: {username} \nPsw: {password}'
	except Exception as e:
		return SERVICE_STATE_MUMBLE,'Module sendmsg.m cant receive flag',str(e)

	return username, password, SERVICE_STATE_UP,'MSNGR up',''

def pull_flag(ip, username, password, flag):
	url = f"https://{ip}:7878/"

	try:
		r = requests.post(url+"getmsg.m", data=f"{username}\x00{password}\x00admin\x00", verify=False, timeout=timeout, headers={'User-Agent' : getRandomUA()})
		if r.status_code != 200:
			return SERVICE_STATE_MUMBLE,'Module getmsg.m cant get messages',f'Status code: {r.status_code}'

		if not flag in r.text:
			return SERVICE_STATE_CORRUPTED,'Module getmsg.m didnt return flag',f'Text: {r.text.strip()}'

	except Exception as e:
		return SERVICE_STATE_MUMBLE,'Module getmsg.m cant get messages',str(e)

	return SERVICE_STATE_UP,'MSNGR up',''

#print(check_functionality('localhost'))
#un,pw,st,ms = push_flag('localhost', 'kekpek')
#print(un,pw,st,ms)
#st,ms = pull_flag('localhost', un, pw, 'kekpek')
#print(un,pw)
