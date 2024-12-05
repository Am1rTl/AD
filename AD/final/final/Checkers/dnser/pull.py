import os
os.environ['PWNLIB_NOTERM'] = '1'

import sys
from redis_lib import RedisDistributor

redisHost = sys.argv[1]
redisPassword = sys.argv[2]
ip = sys.argv[3]
oldFlag = sys.argv[4]

from dnser import pull

D = RedisDistributor(redisHost, redisPassword, 'dnser', 1, ip)

username = D.get_by_flag(oldFlag, 'username')
password = D.get_by_flag(oldFlag, 'password')
recv_ip = D.get_by_flag(oldFlag, 'ip')

status, trace, stderr = pull(ip, username, password, recv_ip, oldFlag)

print(status)
print(trace, flush=True)
print(stderr, file=sys.stderr, flush=True)
