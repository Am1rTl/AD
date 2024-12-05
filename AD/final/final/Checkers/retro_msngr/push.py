from msngr import push_flag
import sys
from redis import StrictRedis

redisHost 		= sys.argv[1]
redisPassword 	= sys.argv[2]
ip 				= sys.argv[3]
newFlag 		= sys.argv[4]


redis 			= StrictRedis(host=redisHost, port=6379, password=redisPassword, decode_responses=True)

un,pw,st,tr,er 	= push_flag(ip, newFlag)

if st == 'UP':
    redis.set(f'checkers_state/msngr/{ip}/username', un)
    redis.set(f'checkers_state/msngr/{ip}/password', pw)

print(st)
print(tr)
print(er, file = sys.stderr)