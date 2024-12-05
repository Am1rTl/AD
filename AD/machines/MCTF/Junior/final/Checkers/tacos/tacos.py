import pwnlib.exception
from pwn import *
from funcs import *
os.environ['PWNLIB_NOTERM'] = '1'

context.log_level = 'CRITICAL'


def check(ip: str) -> tuple:
    try:
        io = init_connection(ip)

        check_system(io)

        username = generate_string(8, 16)
        password = generate_string(8, 16)
        register(io, username, password)
        login(io, username, password)

        data_for_cowsay = generate_string(8, 24)
        check_cowsay(io, data_for_cowsay)

        data_for_notes = generate_string(10, 32)
        check_notes(io, data_for_notes)

        check_program(io)

        check_game(io)
        exit_nicely(io)

    except (pwnlib.exception.PwnlibException, EOFError, BrokenPipeError):
        return STATUS_DOWN, "Cannot connect to server", ""
    except ApiException as e:
        return e.status, e.trace, e.verbose_description
    except Exception as e:
        return STATUS_CORRUPT, "Unexpected problem during functionality checking", str(e)
    return STATUS_UP, "Check is OK", ""

def push(ip: str, new_flag: str) -> tuple:
    try:
        io = init_connection(ip)

        username = generate_string(8, 16)
        password = generate_string(8, 16)
        register(io, username, password)
        login(io, username, password)

        skip_user(io)
        io.sendline(b"notes")

        noteid = write_note(io, new_flag)

        exit_notes(io)
        exit_nicely(io)
    
    except (pwnlib.exception.PwnlibException, EOFError, BrokenPipeError):
        return "", "", "", STATUS_DOWN, "Cannot connect to server", ""
    except ApiException as e:
        return "", "", "", e.status, e.trace, e.verbose_description
    except Exception as e:
        return STATUS_CORRUPT, "Unexpected problem while pushing flag", str(e)
    return username, password, noteid, STATUS_UP, "Push is OK", ""

def pull(ip: str,
        username: str,
        password: str,
        noteid: str,
        old_flag: str) -> tuple:
    try:
        io = init_connection(ip)

        login(io, username, password)

        skip_user(io)
        io.sendline(b"notes")

        flag = read_note(io, noteid)

        if flag != old_flag:
            return STATUS_MUMBLE, "Failed to get a valid flag", ""

        exit_notes(io)
        exit_nicely(io)

    except (pwnlib.exception.PwnlibException, EOFError, BrokenPipeError):
        return STATUS_DOWN, "Cannot connect to server", ""
    except ApiException as e:
        return e.status, e.trace, e.verbose_description
    except Exception as e:
        return STATUS_CORRUPT, "Unexpected problem while receiving flag", str(e)
    return STATUS_UP, "Pull is OK", ""