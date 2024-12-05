from base64 import b64encode, b64decode
from redis import StrictRedis


class RedisDistributor:
    def __init__(self, redisHost: str, redisPassword: str, serviceName: str, vulns: int, ip: str):
        self.r = StrictRedis(host=redisHost, port=6379, password=redisPassword, decode_responses=True)
        self.service_name = serviceName
        self.ip = ip
        self.vulns = vulns

    def push_vuln(self, flag):
        if self.vulns < 2:
            return 0
        vuln = self.r.get(f'checkers_state/{self.service_name}/{self.ip}/vuln')
        if vuln is None:
            vuln = 0
        vuln = int(vuln)
        vuln_new = (vuln + 1) % self.vulns
        self.r.set(f'checkers_state/{self.service_name}/{self.ip}/vuln', vuln_new)
        self.r.set(f'checkers_state/{self.service_name}/{self.ip}/vulns/{flag}', vuln)
        return vuln

    def pull_vuln(self, flag):
        flag_vuln = self.r.get(f'checkers_state/{self.service_name}/{self.ip}/vulns/{flag}')
        assert flag_vuln is not None
        return int(flag_vuln)

    def redis(self):
        return self.r

    def set(self, key, value):
        return self.r.set(f'checkers_state/{self.service_name}/{self.ip}/values/{key}', value)

    def get(self, key):
        return self.r.get(f'checkers_state/{self.service_name}/{self.ip}/values/{key}')

    def set_by_flag(self, flag, key, value):
        return self.r.set(f'checkers_state/{self.service_name}/{self.ip}/values/{key}/{flag}', value)

    def get_by_flag(self, flag, key):
        return self.r.get(f'checkers_state/{self.service_name}/{self.ip}/values/{key}/{flag}')
