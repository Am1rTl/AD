import os
os.environ['PWNLIB_NOTERM'] = '1'

import sys
from redis_lib import RedisDistributor

redisHost = sys.argv[1]
redisPassword = sys.argv[2]
ip = sys.argv[3]
old_flag = sys.argv[4]

from tacos import pull

D = RedisDistributor(redisHost, redisPassword, 'tacos', 1, ip)

username = D.get_by_flag(old_flag, 'username')
password = D.get_by_flag(old_flag, 'password')
noteid = D.get_by_flag(old_flag, 'noteid')

status, trace, stderr = pull(ip, username, password, noteid, old_flag)

print(status)
print(trace, flush=True)
print(stderr, file=sys.stderr, flush=True)
