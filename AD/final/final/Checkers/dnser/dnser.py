import pwnlib.exception
from pwn import *
os.environ['PWNLIB_NOTERM'] = '1'

context.log_level = 'CRITICAL'

from api import (skip_welcome_msg,
                 generate_str,
                 generate_ip,
                 register,
                 ApiException,
                 login,
                 choose_ip,
                 buy_ip,
                 buy_dns,
                 resolve_dns,
                 show_my_dns,
                 exit_)

STATUS_UP = 'UP'
STATUS_DOWN = 'DOWN'
STATUS_CORRUPT = 'CORRUPT'
STATUS_MUMBLE = 'MUMBLE'

PORT = 1337


def check(ip: str) -> tuple:
    try:
        with remote(ip, PORT, timeout=5) as io:
            skip_welcome_msg(io)

            username = generate_str(7, 30)
            password = generate_str(25, 30)
            register(io, username, password)
            login(io, username, password)

            ip = generate_ip()
            choose_ip(io, ip)
            buy_ip(io)
            dns = generate_str(10, 11)
            buy_dns(io, dns)
            if ip not in resolve_dns(io, dns):
                raise ApiException(STATUS_MUMBLE, "Problem with dns resolving")

            exit_(io)
    except (pwnlib.exception.PwnlibException, EOFError):
        return STATUS_DOWN, "Cannot connect to server", ""
    except ApiException as e:
        return e.status, e.trace, e.verbose_description
    return STATUS_UP, "Check is OK", ""


def push(ip: str, new_flag: str) -> tuple:
    try:
        with remote(ip, PORT, timeout=5) as io:
            skip_welcome_msg(io)

            username = generate_str(7, 30)
            password = generate_str(25, 30)
            register(io, username, password)
            login(io, username, password)

            gip = generate_ip()
            choose_ip(io, gip)
            buy_ip(io)
            buy_dns(io, new_flag)

            exit_(io)
    except (pwnlib.exception.PwnlibException, EOFError):
        return "", "", "", STATUS_DOWN, "Cannot connect to server", ""
    except ApiException as e:
        return "", "", "", e.status, e.trace, e.verbose_description
    return username, password, gip, STATUS_UP, "Push is OK", ""


def pull(ip: str, username: str, password: str, recv_ip: str, old_flag: str) -> tuple:
    try:
        with remote(ip, PORT, timeout=5) as io:
            skip_welcome_msg(io)

            login(io, username, password)

            if recv_ip not in resolve_dns(io, old_flag):
                raise ApiException(STATUS_CORRUPT, "Not found user's ip in dns resolver")
            if f"{old_flag}|{recv_ip}" not in show_my_dns(io):
                raise ApiException(STATUS_CORRUPT, "Not found dns in user's storage")

            exit_(io)
    except (pwnlib.exception.PwnlibException, EOFError):
        return STATUS_DOWN, "Cannot connect to server", ""
    except ApiException as e:
        return e.status, e.trace, e.verbose_description
    return STATUS_UP, "Pull is OK", ""
