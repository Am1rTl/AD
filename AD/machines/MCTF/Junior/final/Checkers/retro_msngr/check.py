from msngr import check_functionality
import sys

redisHost = sys.argv[1]
redisPassword = sys.argv[2]
ip = sys.argv[3]

status, trace, stder = check_functionality(ip)
print(status)
print(trace)
print(stder, file = sys.stderr)