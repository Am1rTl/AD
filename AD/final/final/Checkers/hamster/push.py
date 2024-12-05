import sys

from hamster import push1
from redis_lib import RedisDistributor

redisHost = sys.argv[1]
redisPassword = sys.argv[2]
ip = sys.argv[3]
newFlag = sys.argv[4]

D = RedisDistributor(redisHost, redisPassword, 'hamster', 1, ip)
username, password, status, trace, stderr = push1(ip, newFlag)

if status == 'UP':
    D.set_by_flag(newFlag, 'username', username)
    D.set_by_flag(newFlag, 'password', password)

print(status)
print(trace, flush=True)
print(stderr, file=sys.stderr, flush=True)
