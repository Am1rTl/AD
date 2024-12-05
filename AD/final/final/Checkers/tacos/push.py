import os
os.environ['PWNLIB_NOTERM'] = '1'

import sys
from redis_lib import RedisDistributor

redisHost = sys.argv[1]
redisPassword = sys.argv[2]
ip = sys.argv[3]
new_flag = sys.argv[4]

from tacos import push

D = RedisDistributor(redisHost, redisPassword, 'tacos', 1, ip)

vuln = D.push_vuln(new_flag)

username, password, noteid, status, trace, stderr = push(ip, new_flag)

if status == 'UP':
    D.set_by_flag(new_flag, 'username', username)
    D.set_by_flag(new_flag, 'password', password)
    D.set_by_flag(new_flag, 'noteid', noteid)

print(status)
print(trace, flush=True)
print(stderr, file=sys.stderr, flush=True)

