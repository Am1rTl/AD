from msngr import pull_flag
import sys
from redis import StrictRedis

redisHost 		= sys.argv[1]
redisPassword 	= sys.argv[2]
ip 				= sys.argv[3]
oldFlag 		= sys.argv[4]

redis 			= StrictRedis(host=redisHost, port=6379, password=redisPassword, decode_responses=True)

username		= redis.get(f'checkers_state/msngr/{ip}/username')
password 		= redis.get(f'checkers_state/msngr/{ip}/password')

status, trace, stder 	= pull_flag(ip, username, password, oldFlag)
print(status)
print(trace)
print(stder, file = sys.stderr)
