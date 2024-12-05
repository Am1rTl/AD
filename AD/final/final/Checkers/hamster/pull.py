import sys

from hamster import pull1
from redis_lib import RedisDistributor

redisHost = sys.argv[1]
redisPassword = sys.argv[2]
ip = sys.argv[3]
oldFlag = sys.argv[4]

D = RedisDistributor(redisHost, redisPassword, 'hamster', 1, ip)

username = D.get_by_flag(oldFlag, 'username')
password = D.get_by_flag(oldFlag, 'password')
status, trace, stderr = pull1(ip, username, password, oldFlag)

print(status)
print(trace, flush=True)
print(stderr, file=sys.stderr, flush=True)
