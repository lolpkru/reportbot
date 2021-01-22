from colorama import init
from time import sleep
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import requests, ctypes, uuid, os, re, random, socket, json, readchar

r = requests.Session()
hostname = socket.gethostname()
IP = socket.gethostbyname(hostname)
IP_URL = 'https://pastebin.com/raw/VMGJEKub'
IP_CHECK = r.get(IP_URL)
clear = lambda : os.system('cls')

uid = str(uuid.uuid4())

init()
ERROR = "[\x1b[31mERROR\x1b[39m]"
SUCCESS = "[\x1b[32mSUCCESS\x1b[39m]"
INPUT = "[\x1b[33m?\x1b[39m]"
INFO = "[\x1b[35mINFO\x1b[39m]"
CLOSE = "[\x1b[35mCLOSE\x1b[39m]"
PKRU = "\x1b[32mp\x1b[39m \x1b[31mk\x1b[39m \x1b[33mr\x1b[39m \x1b[35mu\x1b[39m"

BREAK = 3
LINE_FEED = 13
BACK_SPACE = 127 if os.name == "posix" else 8

def get_input(prompt, mask=False):
    ret_str = b""
    print(prompt, end="", flush=True)

    while True:
        ch = readchar.readchar()

        if os.name == "posix":
            ch = str.encode(ch)

        code_point = ord(ch)

        if code_point == BREAK:  # Ctrl-C
            if os.name == "posix":
                print("\n", end="", flush=True)

            exit(0)
        elif code_point == LINE_FEED:  # Linefeed
            break
        elif code_point == BACK_SPACE:  # Backspace
            if len(ret_str) > 0:
                ret_str = ret_str[:-1]
                print("\b \b", end="", flush=True)
        else:
            ret_str += ch
            print("*" if mask else ch.decode("utf-8"), end="", flush=True)

    print("\n", end="", flush=True)
    return ret_str.decode("utf-8")

def close():
    get_input("{} Press \x1b[33mENTER\x1b[39m TO {}".format(ERROR, CLOSE))
    exit(0)

clear()
print("[\x1b[32m+\x1b[39m] {} report.".format(PKRU))
print("[\x1b[31m<3\x1b[39m] made with luv <3")
url = 'https://i.instagram.com/api/v1/accounts/login/'
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
with open(os.getcwd() + '\\pool.txt', 'r') as (fd):
    accountpool = fd.read().splitlines()

for account in accountpool:
    username = account.split(':')[0]
    password = account.split(':')[1]


print("{} Logging into: {}\n".format(INFO, username))
data = {
    '_uuid': uid,
    'password': password,
    'username': username,
    'device_id': uid,
    'from_reg': 'false',
    '_csrftoken': 'missing',
    'login_attempt_count': '0'
}
head1 = {
    'User-Agent': 'Instagram 113.0.0.39.122 Android (24/5.0; 515dpi; 1440x2416; huawei/google; Nexus 6P; angler; angler; en_US)',
    'Accept': '*/*',
    'Accept-Encoding': 'gzip,deflate',
    'Accept-Language': 'en-US',
    'X-IG-Capabilities': '3brTvw==',
    'X-IG-Connection-Type': 'WIFI',
    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
    'Host': 'i.instagram.com'
}
response = r.post(url, data=data, headers=head1)
if "The password you entered is incorrect. Please try again." in response.text:
    print('{} incorrect \x1b[33mPASSWORD\x1b[39m'.format(ERROR))
    close()
if "The username you entered doesn't appear to belong to an account. Please check your username and try again." in response.text:
    print('{} incorect \x1b[33mUSERNAME\x1b[39m'.format(ERROR))
    close()
if ('checkpoint_challenge_required') in response.text:
    print("{} @{} IS SUS.".format(ERROR, username))
    close()
if "Sorry, there was a problem with your request." in response.text:
    print("{} A random error occured. ".format(ERROR))
    close()
if "rate_limit_error" in response.text:
    print("{} Rate Limited.".format(ERROR))
    close()




if IP in IP_CHECK.text:
    print("{} IP BLOCKED. FUCK OFF RETARD.".format(ERROR))
    close()
else:
    if 'Closed' in IP_CHECK.text:
        print("{} CLOSED :(".format(ERROR))
        close()

attempt = 0
attempt1 = 0
attempt2 = 0
attempt3 = 0
attempt4 = 0
attempt5 = 0
attempt6 = 0

def previous_ban():
    global target
    pkru_1 = "https://www.instagram.com/"
    repo = requests.get(pkru_1 + target)
    if repo.status_code == 200:
        print("{} Target is not banned.\n".format(SUCCESS))
    if repo.status_code == 404:
        print("{} Target is already banned.".format(ERROR))
        close()

def violence():
    global lol_sleep
    global attempt
    sleep(int(lol_sleep))
    url1 = 'https://www.instagram.com/' + target + '/?_x=1'
    p123 = requests.get(url1).text
    pp = re.search('profilePage_(\\d+)', p123)
    if 'Page Not Found &bull' in p123:
        print("{} @{} banned!".format(SUCCESS, target))
        print("{} Press ENTER to CLOSE".format(SUCCESS))
        exit()
    else:
        report_url = 'https://i.instagram.com/api/v1/users/' + Target + '/flag_user/'
        report_data = {'uuid': str(uuid.uuid4),
                       'reason_id': '5',
                       'source_name': 'profile',
                       '_csrftoken': 'missing'}
        report_headers = {
            'User-Agent': 'Instagram 113.0.0.39.122 Android (24/5.0; 515dpi; 1440x2416; huawei/google; Nexus 6P; angler; angler; en_US)',
            'Accept': '*/*',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'en-US',
            'X-IG-Capabilities': '3brTvw==',
            'X-IG-Connection-Type': 'WIFI',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Host': 'i.instagram.com'}
        r2 = r.post(report_url, data=report_data, headers=report_headers)
        if '{"status": "ok"}' in r2.text:
            attempt += 1
            print("{} VIOLENCE - {}".format(SUCCESS, attempt))
        else:
            print("{} VIOLENCE - FAIL ".format(ERROR))



def spam():
    global attempt1
    global lol_sleep
    sleep(lol_sleep)
    url2 = 'https://www.instagram.com/' + target + '/?_x=1'
    s123 = requests.get(url2).text
    s7 = re.search('profilePage_(\\d+)', s123)
    if 'Page Not Found &bull' in s123:
        print("{} @{} banned!".format(SUCCESS, target))
        print("{} Press ENTER to CLOSE".format(SUCCESS))
        exit()
    else:
        spam_url = 'https://i.instagram.com/api/v1/users/' + Target + '/flag_user/'
        spam_data = {
            'uuid': uid,
            'reason_id': '1',
            'source_name': 'profile',
            '_csrftoken': 'missing'
        }
        spam_headers = {
            'User-Agent': 'Instagram 113.0.0.39.122 Android (24/5.0; 515dpi; 1440x2416; huawei/google; Nexus 6P; angler; angler; en_US)',
            'Accept': '*/*',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'en-US',
            'X-IG-Capabilities': '3brTvw==',
            'X-IG-Connection-Type': 'WIFI',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Host': 'i.instagram.com'
        }
        spammed = r.post(spam_url, data=spam_data, headers=spam_headers)
        if '{"status": "ok"}' in spammed.text:
            attempt1 += 1
            print("{} SPAM - {}".format(SUCCESS, attempt1))
        else:
            print("{} SPAM - FAIL".format(ERROR))

def harassment():
    global attempt2
    global lol_sleep
    sleep(lol_sleep)
    url3 = 'https://www.instagram.com/' + target + '/?_x=1'
    l123 = requests.get(url3).text
    p8 = re.search('profilePage_(\\d+)', l123)
    if 'Page Not Found &bull' in l123:
        print("{} @{} banned!".format(SUCCESS, target))
        print("{} Press ENTER to CLOSE".format(SUCCESS))
        exit()
    else:
        harrassment_url = 'https://i.instagram.com/api/v1/users/' + Target + '/flag_user/'
        harrassment_data = {
            'uuid': uid,
            'reason_id': '7',
            'source_name': 'profile',
            '_csrftoken': 'missing'
        }
        harrassment_headers = {
            'User-Agent': 'Instagram 113.0.0.39.122 Android (24/5.0; 515dpi; 1440x2416; huawei/google; Nexus 6P; angler; angler; en_US)',
            'Accept': '*/*',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'en-US',
            'X-IG-Capabilities': '3brTvw==',
            'X-IG-Connection-Type': 'WIFI',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Host': 'i.instagram.com'
        }
        harrased = r.post(harrassment_url, data=harrassment_data, headers=harrassment_headers)
        if '{"status": "ok"}' in harrased.text:
            attempt2 += 1
            print("{} HARASSMENT - {}".format(SUCCESS, attempt2))
        else:
            print("{} HARASSMENT - FAIL".format(ERROR))

def harm():
    global attempt3
    sleep(lol_sleep)
    url4 = 'https://www.instagram.com/' + target + '/?_x=1'
    lol = requests.get(url4).text
    p9 = re.search('profilePage_(\\d+)', lol)
    if "Page Not Found &bull" in lol:
        print("{} @{} banned!".format(SUCCESS, target))
        print("{} Press ENTER to CLOSE".format(SUCCESS))
        exit()
    else:
        harm_url = 'https://i.instagram.com/api/v1/users/' + Target + '/flag_user/'
        harm_data = {
            'reason_id': '2',
            'source_name': 'profile',
            '_csrftoken': 'missing'
        }
        harm_headers = {
            'User-Agent': 'Instagram 113.0.0.39.122 Android (24/5.0; 515dpi; 1440x2416; huawei/google; Nexus 6P; angler; angler; en_US)',
            'Accept': '*/*',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'en-US',
            'X-IG-Capabilities': '3brTvw==',
            'X-IG-Connection-Type': 'WIFI',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Host': 'i.instagram.com'
        }
        harmmed = r.post(harm_url, data=harm_data, headers=harm_headers)
        if '{"status": "ok"}' in harmmed.text:
            attempt3 += 1
            print("{} SELF HARM - {}".format(SUCCESS, attempt3))
        else:
            print("{} SELF HARM - FAIL".format(ERROR))

def nudity():
    global attempt4
    global lol_sleep
    sleep(lol_sleep)
    url5 = 'https://www.instagram.com/' + target + '/?_x=1'
    poop = requests.get(url5).text
    p10 = re.search('profilePage_(\\d+)', poop)
    if 'Page Not Found &bull' in poop:
        print("{} @{} banned!".format(SUCCESS, target))
        print("{} Press ENTER to CLOSE".format(SUCCESS))
        exit()
    else:
        nudity_url = 'https://i.instagram.com/api/v1/users/' + Target + '/flag_user/'
        nudity_data = {
            'reason_id': '4',
            'source_name': 'profile',
            '_csrftoken': 'missing'
        }
        nudity_headers = {
            'User-Agent': 'Instagram 113.0.0.39.122 Android (24/5.0; 515dpi; 1440x2416; huawei/google; Nexus 6P; angler; angler; en_US)',
            'Accept': '*/*',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'en-US',
            'X-IG-Capabilities': '3brTvw==',
            'X-IG-Connection-Type': 'WIFI',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Host': 'i.instagram.com'
        }
        n5 = r.post(nudity_url, data=nudity_data, headers=nudity_headers)
        if '{"status": "ok"}' in n5.text:
            attempt4 += 1
            print("{} NUDITY - {}".format(SUCCESS, attempt4))
        else:
            print("{} NUDITY - FAIL".format(ERROR))

def hate():
    global attempt5
    global lol_sleep
    sleep(lol_sleep)
    url6 = 'https://www.instagram.com/' + target + '/?_x=1'
    r123 = requests.get(url6).text
    pll = re.search('profilePage_(\\d+)', r123)
    if 'Page Not Found &bull' in r123:
        print("{} @{} banned!".format(SUCCESS, target))
        print("{} Press ENTER to CLOSE".format(SUCCESS))
        exit()
    else:
        hate_url = 'https://i.instagram.com/api/v1/users/' + Target + '/flag_user/'
        hate_data = {
            'reason_id': '6',
            'source_name': 'profile',
            '_csrftoken': 'missing'
        }
        hate_headers = {
            'User-Agent': 'Instagram 113.0.0.39.122 Android (24/5.0; 515dpi; 1440x2416; huawei/google; Nexus 6P; angler; angler; en_US)',
            'Accept': '*/*',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'en-US',
            'X-IG-Capabilities': '3brTvw==',
            'X-IG-Connection-Type': 'WIFI',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Host': 'i.instagram.com'
        }
        rainbow = r.post(hate_url, data=hate_data, headers=hate_data)
        if '{"status": "ok"}' in rainbow.text:
            attempt5 += 1
            print("{} HATE - {}".format(SUCCESS, attempt5))
        else:
            print("{} HATE - FAIL".format(ERROR))
            print(response.text)


def sale():
    global attempt6
    global lol_sleep
    sleep(lol_sleep)
    url100 = 'https://www.instagram.com/' + target + '/?_x=1'
    re123 = requests.get(url100).text
    p12 = re.search('profilePage_(\\d+)', re123)
    if 'Page Not Found &bull' in re123:
        print("{} @{} banned!".format(SUCCESS, target))
        print("{} Press ENTER to CLOSE".format(SUCCESS))
        exit()
    else:
        sale_url = 'https://i.instagram.com/api/v1/users/' + Target + '/flag_user/'
        sale_data = {
            'reason_id': '6',
            'source_name': 'profile',
            '_csrftoken': 'missing'
        }
        sale_headers = {
            'User-Agent': 'Instagram 113.0.0.39.122 Android (24/5.0; 515dpi; 1440x2416; huawei/google; Nexus 6P; angler; angler; en_US)',
            'Accept': '*/*',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'en-US',
            'X-IG-Capabilities': '3brTvw==',
            'X-IG-Connection-Type': 'WIFI',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Host': 'i.instagram.com'
        }
        sold = r.post(sale_url, data=sale_data, headers=sale_headers)
        if '{"status": "ok:}' in sold.text:
            attempt6 += 1
            print("{} SALE - {}".format(SUCCESS, attempt6))
        else:
            print("{} SALE - FAIL".format(ERROR))

def start():
    global mode
    if 'all' in mode:
        spam()
        harm()
        violence()
        harassment()
        nudity()
    if "ALL" in mode:
        spam()
        harm()
        violence()
        harassment()
        nudity()
    if '1' in mode:
        violence()
    if '2' in mode:
        spam()
    if '3' in mode:
        harassment()
    if '4' in mode:
        harm()
    if '5' in mode:
        nudity()


if ('"logged_in_user"') in response.text:
    print("{} Logged in!".format(SUCCESS))
    target = get_input('{} Target: '.format(INPUT))
    print("{} Checking for ban...".format(INFO))
    previous_ban()
    lol_sleep = int(get_input('{} Sleep [SEC]: '.format(INPUT)))
    mode = get_input(
        "\n{} Report MODE:\n(1 - violence, 2 - spam, 3 - harassment, 4 - self harm, 5 - nudity, or ALL): ".format(
            INPUT))
    url5 = 'https://www.instagram.com/' + target + '/?_x=1'
    r555 = requests.get(url5).text
    pe = re.search('profilePage_(\\d+)', r555)
    if '176532891' in r555:
        print("{} FUCK YOU {}".format(INFO, IP))
        print("{} DONT TRY REPORTING ME!!!".format(ERROR))
        close()

    if 'Page Not Found &bull' in r555:
        print("{} @{} already banned!".format(SUCCESS, target))
        close()
    Target = pe.group(1)
    while True:
        start()





