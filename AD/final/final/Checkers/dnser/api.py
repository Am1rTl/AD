from pwn import *
from string import ascii_letters, digits
import random
import os
os.environ['PWNLIB_NOTERM'] = '1'

TIMEOUT = 5
STATUS_UP = 'UP'
STATUS_DOWN = 'DOWN'
STATUS_CORRUPT = 'CORRUPT'
STATUS_MUMBLE = 'MUMBLE'


class ApiException(Exception):
    status: str
    trace: str
    verbose_description: str

    def __init__(self, status, trace, verbose_description=""):
        self.status = status
        self.trace = trace
        self.verbose_description = verbose_description


def generate_str(min_len: int, max_len: int, letters=ascii_letters + digits) -> str:
    return "".join([random.choice(letters) for _ in range(random.randint(min_len, max_len))])


def generate_ip() -> str:
    return ".".join(str(random.randint(0, 255)) for _ in range(4))


def skip_welcome_msg(io: remote) -> None:
    try:
        io.recvuntil(b"\n\n\n", timeout=TIMEOUT)
    except Exception as e:
        raise ApiException(STATUS_DOWN, "Connection failed", str(e))


def register(io: remote, username: str, password: str) -> None:
    try:
        io.sendline(f"0|0|{username}".encode())
        status = io.recvline(timeout=TIMEOUT)
        if b"Created user" not in status:
            raise ApiException(STATUS_MUMBLE, "Problem with STATE_REG_USERNAME", status)
        io.sendline(f"0|1|{password}".encode())
        status = io.recvline(timeout=TIMEOUT)
        if b"Password is defined" not in status:
            raise ApiException(STATUS_MUMBLE, "Problem with STATE_REG_PASS", status)
    except BrokenPipeError as e:
        raise ApiException(STATUS_DOWN, "Connection failed", str(e))
    except EOFError as e:
        raise ApiException(STATUS_MUMBLE, "Failed to register", str(e))


def login(io: remote, username: str, password: str) -> None:
    try:
        io.sendline(f"1|0|{username}".encode())
        status = io.recvline(timeout=TIMEOUT)
        if b"Enter password!" not in status:
            raise ApiException(STATUS_MUMBLE, "Problem with STATE_LOGIN_USERNAME", status)
        io.sendline(f"1|1|{password}".encode())
        status = io.recvline(timeout=TIMEOUT)
        if b"You're logged in!" not in status:
            raise ApiException(STATUS_MUMBLE, "Problem with STATE_LOGIN_PASS", status)
    except BrokenPipeError as e:
        raise ApiException(STATUS_DOWN, "Connection failed", str(e))
    except EOFError as e:
        raise ApiException(STATUS_MUMBLE, "Failed to register", str(e))


def choose_ip(io: remote, ip: str) -> None:
    try:
        io.sendline(f"2|0|{ip}".encode())
        status = io.recvline(timeout=TIMEOUT)
        if b"Ok" not in status:
            raise ApiException(STATUS_MUMBLE, "Problem with STATE_IP_CHOOSE", status)
    except BrokenPipeError as e:
        raise ApiException(STATUS_DOWN, "Connection failed", str(e))
    except EOFError as e:
        raise ApiException(STATUS_MUMBLE, "Failed to choose ip", str(e))


def buy_ip(io: remote) -> None:
    try:
        io.sendline(b"2|1|stub")
        status = io.recvline(timeout=TIMEOUT)
        if b"IP was bought" not in status:
            raise ApiException(STATUS_MUMBLE, "Problem with STATE_IP_BUY", status)
    except BrokenPipeError as e:
        raise ApiException(STATUS_DOWN, "Connection failed", str(e))
    except EOFError as e:
        raise ApiException(STATUS_MUMBLE, "Failed to buy ip", str(e))


def buy_dns(io: remote, dns: str) -> None:
    try:
        io.sendline(f"3|0|{dns}".encode())
        status = io.recvline(timeout=TIMEOUT)
        if B"DNS was bought" not in status:
            raise ApiException(STATUS_MUMBLE, "Problem with STATE_DNS_BUY", status)
    except BrokenPipeError as e:
        raise ApiException(STATUS_DOWN, "Connection failed", str(e))
    except EOFError as e:
        raise ApiException(STATUS_MUMBLE, "Failed to buy dns", str(e))


def resolve_dns(io: remote, dns: str) -> str:
    try:
        io.sendline(f"3|1|{dns}".encode())  # ACTION_DNS|STATE_DNS_RESOLVE|
        status = io.recvline(timeout=TIMEOUT)
        if b"Resolve result: " not in status:
            raise ApiException(STATUS_MUMBLE, "Problem with STATE_DNS_RESOLVE", status)
        return status.decode()
    except BrokenPipeError as e:
        raise ApiException(STATUS_DOWN, "Connection failed", str(e))
    except EOFError as e:
        raise ApiException(STATUS_MUMBLE, "Failed to resolve dns", str(e))


def show_my_dns(io: remote) -> str:
    io.sendline(b"4|3|stub")  # ACTION_SHOW|STATE_SHOW_MY_DOMAINS|
    status = io.recvline(timeout=TIMEOUT)
    if b"My domains: " not in status:
        raise ApiException(STATUS_MUMBLE, "Problem with STATE_SHOW_MY_DOMAINS", status)

    status += io.recvline(timeout=TIMEOUT)
    return status.decode()


def exit_(io: remote) -> None:
    io.sendline(b"6|0|stub")
