import os
import json
from pwn import *

context.log_level='critical'

# open file with answers data
if not os.path.isfile('answers'):
    json.dump({}, open('answers', 'w'))

answers = json.load(open('answers'))

# starting brute
flag = ""
while "MCTF" not in flag:
    s = remote("localhost", 4444)

    s.recvuntil("---------------".encode())
    s.recvline()
    s.recvline()

    for i in range(100):
        data = s.recvline().decode()
        s.recvline()

        # retrieve answers from task
        a_b = s.recvline().decode().replace(' ', '').replace('\n', '').split('\t\t')
        c_d = s.recvline().decode().replace(' ', '').replace('\n', '').split('\t\t')

        # look for the answer in file
        if data in answers:
            result = answers[data]
            
            if result in a_b[0]:
                send_answer = "A\n"
            elif result in a_b[1]:
                send_answer = "B\n"
            elif result in c_d[0]:
                send_answer = "C\n"
            elif result in c_d[1]:
                send_answer = "D\n"

            s.send(send_answer.encode())

            s.recvline()
            s.recvline()
        else:
            # sending test answer
            s.send("A\n".encode())
            s.recvline()
            status = s.recvline().decode()

            # write right answer
            if "Correct!" not in status:
                result = s.recvline().decode().replace('\n', '').split()
                answers[data] = result[-1]
                s.recvline()

    with open('answers', 'w') as f:
        json.dump(answers, f)

    flag = s.recvline().decode()
    s.close()

print(flag)