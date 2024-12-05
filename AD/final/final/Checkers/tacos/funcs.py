from pwn import *
from string import ascii_uppercase, ascii_lowercase, digits
from time import time
import random

PORT = 1488
TIMEOUT = 5
STATUS_UP = 'UP'
STATUS_DOWN = 'DOWN'
STATUS_CORRUPT = 'CORRUPT'
STATUS_MUMBLE = 'MUMBLE'
random.seed(time())

class ApiException(Exception):
    status: str
    trace: str
    verbose_description: str

    def __init__(self, status, trace, verbose_description=""):
        self.status = status
        self.trace = trace
        self.verbose_description = verbose_description


def generate_string(min_length: int = 8,
                    max_length: int = 16,
                    alphabet: str = ascii_lowercase + ascii_uppercase + digits) -> str:
    symbols = random.choices(alphabet, k=random.randint(min_length, max_length))
    return "".join(symbols)

def init_connection(ip: str) -> pwnlib.tubes.remote.remote:
    io = remote(ip, PORT, timeout=TIMEOUT)
    return io

def check_system(io: pwnlib.tubes.remote.remote):
    try:
        for i in range(12):
            io.recvline(timeout=TIMEOUT)
        system_version = io.recvline(timeout=TIMEOUT)
        if b"6.12.1-arch1-1" not in system_version:
            raise ApiException(STATUS_MUMBLE, "Failed to get system info", "")
        
    except BrokenPipeError as e:
        raise ApiException(STATUS_DOWN, "Connection failed", str(e))
    except EOFError as e:
        raise ApiException(STATUS_MUMBLE, "Failed to get system info", str(e))
    

def skip_user(io: pwnlib.tubes.remote.remote) -> None:
    io.recvuntil(b"@tacos> ", timeout=TIMEOUT)

def register(io: pwnlib.tubes.remote.remote,
            username: str,
            password: str) -> None:
    try:
        skip_user(io)

        io.sendline(b"register")

        io.recvuntil(b"username: ", timeout=TIMEOUT)
        io.sendline(username.encode())

        io.recvuntil(b"password: ", timeout=TIMEOUT)
        io.sendline(password.encode())

        status = io.recvline()

        if b"successfully" not in status:
            raise ApiException(STATUS_MUMBLE, "Failed to register", "")

    except BrokenPipeError as e:
        raise ApiException(STATUS_DOWN, "Connection failed", str(e))
    except EOFError as e:
        raise ApiException(STATUS_MUMBLE, "Failed to register", str(e))

def login(io: pwnlib.tubes.remote.remote,
            username: str,
            password: str) -> None:
    try:
        skip_user(io)

        io.sendline(b"login")

        io.recvuntil(b"username: ", timeout=TIMEOUT)
        io.sendline(username.encode())

        io.recvuntil(b"password: ", timeout=TIMEOUT)
        io.sendline(password.encode())

        status = io.recvline(timeout=TIMEOUT)

        if b"successfully" not in status:
            raise ApiException(STATUS_MUMBLE, "Failed to login", "")
        
    except BrokenPipeError as e:
        raise ApiException(STATUS_DOWN, "Connection failed", str(e))
    except EOFError as e:
        raise ApiException(STATUS_MUMBLE, "Failed to login", str(e))


def write_note(io: pwnlib.tubes.remote.remote,
            data: str) -> str:
    try:
        io.recvuntil(b"Enter your choice: ", timeout=TIMEOUT)
        io.sendline(b"1")

        io.recvuntil(b"Enter data to put into note: ", timeout=TIMEOUT)
        io.sendline(data.encode())

        status = io.recvline(timeout=TIMEOUT)
        if b"successfully" not in status:
            raise ApiException(STATUS_MUMBLE, "Failed to write note", "")
        
        io.recvuntil(b"Note ID: ")
        noteid = io.recvline(timeout=TIMEOUT).decode().rstrip()

        return noteid

    except BrokenPipeError as e:
        raise ApiException(STATUS_DOWN, "Connection failed", str(e))
    except EOFError as e:
        raise ApiException(STATUS_MUMBLE, "Failed to write note", str(e))

def read_note(io: pwnlib.tubes.remote.remote,
            noteid: str) -> str:
    try:
        io.recvuntil(b"Enter your choice: ", timeout=TIMEOUT)
        io.sendline(b"2")

        io.recvuntil(b"Enter note id: ", timeout=TIMEOUT)
        io.sendline(noteid.encode())

        data = io.recvline(timeout=TIMEOUT).decode().rstrip()

        return data

    except BrokenPipeError as e:
        raise ApiException(STATUS_DOWN, "Connection failed", str(e))
    except EOFError as e:
        raise ApiException(STATUS_MUMBLE, "Failed to read note", str(e))

def delete_note(io: pwnlib.tubes.remote.remote,
            noteid: str) -> str:
    try:
        io.recvuntil(b"Enter your choice: ", timeout=TIMEOUT)
        io.sendline(b"3")

        io.recvuntil(b"Enter note id: ", timeout=TIMEOUT)
        io.sendline(noteid.encode())

        status = io.recvline(timeout=TIMEOUT)

        if b"successfully" not in status:
            raise ApiException(STATUS_MUMBLE, "Failed to delete note", "")

    except BrokenPipeError as e:
        raise ApiException(STATUS_DOWN, "Connection failed", str(e))
    except EOFError as e:
        raise ApiException(STATUS_MUMBLE, "Failed to delete note", str(e))

def exit_notes(io: pwnlib.tubes.remote.remote) -> None:
    try:
        io.recvuntil(b"Enter your choice: ", timeout=TIMEOUT)
        io.sendline(b"4")
    except BrokenPipeError as e:
        raise ApiException(STATUS_DOWN, "Connection failed", str(e))
    except EOFError as e:
        raise ApiException(STATUS_MUMBLE, "Failed while exiting notes", str(e))

def check_cowsay(io: pwnlib.tubes.remote.remote,
                data: str) -> None:
    try:
        skip_user(io)

        io.sendline(b"cowsay")

        io.recvuntil(b"Enter your message: ", timeout=TIMEOUT)
        io.sendline(data.encode())

        io.recvuntil(b"< ", timeout=TIMEOUT)
        recv_data = io.recvuntil(b" >", timeout=TIMEOUT).decode()[:-2]

        if recv_data != data:
            raise ApiException(STATUS_MUMBLE, "Failed to get valid string", "")
    except BrokenPipeError as e:
        raise ApiException(STATUS_DOWN, "Connection failed", str(e))
    except EOFError as e:
        raise ApiException(STATUS_MUMBLE, "Failed while running cowsay", str(e))

def check_notes(io: pwnlib.tubes.remote.remote,
                data: str) -> None:
    try:
        skip_user(io)

        io.sendline(b"notes")

        noteid = write_note(io, data)
        recv_data = read_note(io, noteid)

        if recv_data != data:
            raise ApiException(STATUS_MUMBLE, "Failed to get valid note data", "")
        
        delete_note(io, noteid)

        exit_notes(io)
    except BrokenPipeError as e:
        raise ApiException(STATUS_DOWN, "Connection failed", str(e))
    except EOFError as e:
        raise ApiException(STATUS_MUMBLE, "Failed while running notes", str(e))

def skip_program_banner(io: pwnlib.tubes.remote.remote) -> None:
    io.recvuntil(b"$ ", timeout=TIMEOUT)

def check_program(io: pwnlib.tubes.remote.remote) -> None:
    try:
        skip_user(io)

        io.sendline(b"program")

        skip_program_banner(io)
        io.sendline(b"1")
        io.recvuntil(b"User: ", timeout=TIMEOUT)
        io.sendline(b"user")
        io.recvuntil(b"Pass: ", timeout=TIMEOUT)
        io.sendline(b"resu")

        status = io.recvline(timeout=TIMEOUT)

        if b"logged in" not in status:
            raise ApiException(STATUS_MUMBLE, "Error while logging into the program", "")
        
        skip_program_banner(io)
        io.sendline(b"2")

        status = io.recvline(timeout=TIMEOUT)

        if b"Your name: user" not in status:
            raise ApiException(STATUS_MUMBLE, "Error while getting user info", "")
        
        skip_program_banner(io)
        io.sendline(b"3")
        io.recvuntil(b"Enter new name: ", timeout=TIMEOUT)
        io.sendline(b"user2")

        skip_program_banner(io)
        io.sendline(b"2")

        status = io.recvline(timeout=TIMEOUT)

        if b"Your name: user2" not in status:
            raise ApiException(STATUS_MUMBLE, "Error while changing name", "")
        
        skip_program_banner(io)
        io.sendline(b"0")
        io.recvline(timeout=TIMEOUT)
        io.recvline(timeout=TIMEOUT)
        io.recvline(timeout=TIMEOUT)
        io.sendline()
        
    except BrokenPipeError as e:
        raise ApiException(STATUS_DOWN, "Connection failed", str(e))
    except EOFError as e:
        raise ApiException(STATUS_MUMBLE, "Failed while running program", str(e))

def check_game(io: pwnlib.tubes.remote.remote) -> None:
    try:
        skip_user(io)

        io.sendline(b"game")
        io.recvuntil(b"quit the game\n", timeout=TIMEOUT)
        io.sendline(b"s")

        while True:
            status = io.recvline(timeout=TIMEOUT)
            if b"Red or Black" not in status:
                break
            io.sendline(b"red")
            status = io.recvline(timeout=TIMEOUT)
        
        name = generate_string(4, 7)
        io.recvuntil(b"Enter your name: ", timeout=TIMEOUT)
        io.sendline(name.encode())

        io.recvuntil(b"quit the game\n", timeout=TIMEOUT)
        io.sendline(b"q")

    except BrokenPipeError as e:
        raise ApiException(STATUS_DOWN, "Connection failed", str(e))
    except EOFError as e:
        raise ApiException(STATUS_MUMBLE, "Failed while running game", str(e))

def exit_nicely(io: pwnlib.tubes.remote.remote) -> None:
    skip_user(io)

    io.sendline(b"exit")