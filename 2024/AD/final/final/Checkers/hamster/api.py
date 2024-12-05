import requests

STATUS_UP = 'UP'
STATUS_DOWN = 'DOWN'
STATUS_CORRUPT = 'CORRUPT'
STATUS_MUMBLE = 'MUMBLE'


class ApiException(Exception):
    status: str
    trace: str
    verbose_description: str

    def __init__(self, status, trace, verbose_description):
        self.status = status
        self.trace = trace
        self.verbose_description = verbose_description


def get_html(session: requests.Session, url: str, path: str):
    try:
        answer = session.get(f'{url}{path}')
        answer.raise_for_status()
        return answer.text
    except requests.Timeout as e:
        raise ApiException(STATUS_DOWN, 'Connection timed out', str(e))
    except requests.ConnectionError as e:
        raise ApiException(STATUS_DOWN, 'Connection failed', str(e))
    except requests.HTTPError as e:
        raise ApiException(STATUS_MUMBLE, f'Unexpected status code {answer.status_code}', str(e))
    except Exception as e:
        raise ApiException(STATUS_DOWN, 'Failed to get main page', str(e))


def register(session: requests.Session, url: str, username: str, password: str):
    try:
        data = {'username': username, 'password': password}
        answer = session.post(f'{url}/register', data=data)
        answer.raise_for_status()
    except requests.Timeout as e:
        raise ApiException(STATUS_DOWN, 'Connection timed out', str(e))
    except requests.ConnectionError as e:
        raise ApiException(STATUS_DOWN, 'Connection failed', str(e))
    except requests.HTTPError as e:
        raise ApiException(STATUS_MUMBLE, f'Failed to register: unexpected status code {answer.status_code}', str(e))
    except Exception as e:
        raise ApiException(STATUS_DOWN, 'Failed to register', str(e))


def login(session: requests.Session, url: str, username: str, password: str):
    try:
        data = {'username': username, 'password': password}
        answer = session.post(f'{url}/login', data=data)
        answer.raise_for_status()
    except requests.Timeout as e:
        raise ApiException(STATUS_DOWN, 'Connection timed out', str(e))
    except requests.ConnectionError as e:
        raise ApiException(STATUS_DOWN, 'Connection failed', str(e))
    except requests.HTTPError as e:
        raise ApiException(STATUS_MUMBLE, f'Failed to log in: unexpected status code {answer.status_code}', str(e))
    except Exception as e:
        raise ApiException(STATUS_DOWN, 'Failed to log in', str(e))


def update_score(session: requests.Session, url: str, score: int):
    try:
        data = {'score': score}
        answer = session.post(f'{url}/update_score', json=data)
        answer.raise_for_status()
    except requests.Timeout as e:
        raise ApiException(STATUS_DOWN, 'Connection timed out', str(e))
    except requests.ConnectionError as e:
        raise ApiException(STATUS_DOWN, 'Connection failed', str(e))
    except requests.HTTPError as e:
        raise ApiException(STATUS_MUMBLE, f'Failed to update score: unexpected status code {answer.status_code}', str(e))
    except Exception as e:
        raise ApiException(STATUS_DOWN, 'Failed to update score', str(e))


def change_recovery(session: requests.Session, url: str, recovery: str):
    try:
        data = {'recovery_code': recovery}
        answer = session.post(f'{url}/update_recovery', data=data)
        answer.raise_for_status()
    except requests.Timeout as e:
        raise ApiException(STATUS_DOWN, 'Connection timed out', str(e))
    except requests.ConnectionError as e:
        raise ApiException(STATUS_DOWN, 'Connection failed', str(e))
    except requests.HTTPError as e:
        raise ApiException(STATUS_MUMBLE, f'Failed to change recovery code: unexpected status code {answer.status_code}', str(e))
    except Exception as e:
        raise ApiException(STATUS_DOWN, 'Failed to change recovery code', str(e))


def change_avatar(session: requests.Session, url: str, avatar: int, id: int):
    try:
        data = {'id': id, 'avatar': avatar}
        answer = session.post(f'{url}/update_avatar', data=data)
        answer.raise_for_status()
    except requests.Timeout as e:
        raise ApiException(STATUS_DOWN, 'Connection timed out', str(e))
    except requests.ConnectionError as e:
        raise ApiException(STATUS_DOWN, 'Connection failed', str(e))
    except requests.HTTPError as e:
        raise ApiException(STATUS_MUMBLE, f'Failed to change avatar: unexpected status code {answer.status_code}', str(e))
    except Exception as e:
        raise ApiException(STATUS_DOWN, 'Failed to change avatar', str(e))