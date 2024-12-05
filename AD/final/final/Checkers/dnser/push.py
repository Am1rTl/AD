import os
os.environ['PWNLIB_NOTERM'] = '1'

import sys
from redis_lib import RedisDistributor

redisHost = sys.argv[1]
redisPassword = sys.argv[2]
ip = sys.argv[3]
newFlag = sys.argv[4]

from dnser import push

D = RedisDistributor(redisHost, redisPassword, 'dnser', 1, ip)

vuln = D.push_vuln(newFlag)

username, password, gip, status, trace, stderr = push(ip, newFlag)

if status == 'UP':
    D.set_by_flag(newFlag, 'username', username)
    D.set_by_flag(newFlag, 'password', password)
    D.set_by_flag(newFlag, 'ip', gip)

print(status)
print(trace, flush=True)
print(stderr, file=sys.stderr, flush=True)

