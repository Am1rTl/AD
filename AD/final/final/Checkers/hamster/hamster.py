import random
import string
import jwt
from requests.adapters import HTTPAdapter, Response
from user_agent import generate_user_agent
from bs4 import BeautifulSoup

from api import *

timeout = 3
PORT = 9000


class TimeoutHTTPAdapter(HTTPAdapter):
    def send(self, *args, **kwargs) -> Response:
        kwargs['timeout'] = timeout
        return super().send(*args, **kwargs)


def generate_str():
    """Generate a random string of fixed length."""
    letters = string.ascii_letters + string.digits
    return ''.join(random.choice(letters) for _ in range(10, random.randint(20, 30)))


def check(ip):
    global comments
    url = f'http://{ip}:{PORT}'
    try:
        with requests.Session() as session:
            session.mount('https://', TimeoutHTTPAdapter(max_retries=2))
            session.mount('http://', TimeoutHTTPAdapter(max_retries=2))
            session.verify = False
            session.headers['User-Agent'] = generate_user_agent()

            username = generate_str()
            password = generate_str()

            # register and login
            get_html(session, url, "/register")
            register(session, url, username, password)
            get_html(session, url, "/")
            login(session, url, username, password)

            # play game
            get_html(session, url, f"/game")
            score = random.randint(1, 20)
            update_score(session, url, score)
            resp = get_html(session, url, f"/scoreboard")
            if f'<td>{username}</td>' not in resp:
                raise ApiException(STATUS_CORRUPT, 'Not displayed in scoreboard', '')

            # change recovery code
            new_recovery = generate_str()
            get_html(session, url, "/profile")
            change_recovery(session, url, new_recovery)
            resp = get_html(session, url, "/profile")
            if f'{new_recovery}' not in resp:
                raise ApiException(STATUS_CORRUPT, 'Can not update recovery code', '')

            # change avatar
            new_avatar = random.randint(2, 4)
            session_cookie = session.cookies.get('session')
            jwt_payload = jwt.decode(session_cookie, options={"verify_signature": False})
            user_id = jwt_payload['user_id']
            change_avatar(session, url, new_avatar, user_id)
            resp = get_html(session, url, "/profile")
            if f'<img src="/static/img/{new_avatar}.jpg" alt="Avatar" id="profile_image">' not in resp:
                raise ApiException(STATUS_CORRUPT, 'Can not update avatar')
    except ApiException as e:
        return e.status, e.trace, e.verbose_description
    return STATUS_UP, 'All functionality checks passed', ''


def push1(ip, flag):
    global comments
    url = f'http://{ip}:{PORT}'
    try:
        with requests.Session() as session:
            session.mount('https://', TimeoutHTTPAdapter(max_retries=2))
            session.mount('http://', TimeoutHTTPAdapter(max_retries=2))
            session.verify = False
            session.headers['User-Agent'] = generate_user_agent()

            username = generate_str()
            password = generate_str()
            get_html(session, url, "/register")
            register(session, url, username, password)
            get_html(session, url, "/")
            login(session, url, username, password)

            # play game
            get_html(session, url, f"/game")
            score = random.randint(1, 20)
            update_score(session, url, score)
            resp = get_html(session, url, f"/scoreboard")
            if f'<td>{username}</td>' not in resp:
                raise ApiException(STATUS_CORRUPT, 'Not displayed in scoreboard', '')
            change_recovery(session, url, flag)
    except ApiException as e:
        return '', '', e.status, e.trace, e.verbose_description
    return username, password, STATUS_UP, 'Flag successfully pushed', ''


def pull1(ip, username, password, flag):
    url = f'http://{ip}:{PORT}'
    try:
        with requests.Session() as session:
            session.mount('https://', TimeoutHTTPAdapter(max_retries=2))
            session.mount('http://', TimeoutHTTPAdapter(max_retries=2))
            session.verify = False
            session.headers['User-Agent'] = generate_user_agent()

            login(session, url, username, password)
            resp = get_html(session, url, "/profile")
            if f'{flag}' not in resp:
                raise ApiException(STATUS_CORRUPT, 'Flag pull failed', '')
    except ApiException as e:
        return e.status, e.trace, e.verbose_description
    except AttributeError:
        return STATUS_MUMBLE, 'Unknown flag pull error', ''
    return STATUS_UP, 'Flag successfully pulled', ''
