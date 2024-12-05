import sys

from tacos import check

redisHost = sys.argv[1]
redisPassword = sys.argv[2]
ip = sys.argv[3]

status, trace, stderr = check(ip)
print(status)
print(trace, flush=True)
print(stderr, file=sys.stderr, flush=True)
