# MCTF Task: nessat 

**Категории:** crypto

### Описание

RU:
Иногда это самое главное

EN:
Sometimes that’s the most important thing
```
nc mctf-game.ru 7576
```

### Writeup
```
from csidh import *
from ecdsa import *
from tqdm import tqdm
from random import choices
from hashlib import sha256
from itertools import product


def rand_bytes(size=10):
    return bytes(choices(list(range(256)), k=size))


def solve_captcha(s):
    while True:
        b = rand_bytes()
        h = sha256(b).hexdigest()
        if h.startswith(s):
            return b.hex()


def brute(known: list[int], A: int):
    for i in tqdm(product([-1, 1], repeat=len(primes) - len(known))):
        t = known.copy() + list(i)
        if int(group_action(0, t)) == A:
            return t
    return None


#print(solve_captcha('b18c8'))


k1 = [-1, 1] * 12
k2 = [1, -1] * 12
A = 16429126563496291754283555136323242106794205355
p1 = brute(k1, A)
if p1 is None:
    p1 = brute(k2, A)

bob_private = [-i for i in p1]
bob_public = group_action(0, bob_private)
print(f"{bob_public = }")

curve = to_weierstrass(0)
qx, qy = (15981310533908543804336606659060654155538537851, 18159024189910045003688397496430933193596240325)
Q = curve((qx, qy))
G = curve.gens()[0]
d = Q.log(G)
ecdsa = ECDSA(curve, private=d)
r, s = (ecdsa.sign(b'amogus'))
print(f"{r = }")
print(f"{s = }")

```

### Flag
```
MCTF{0b055415y4_s_n0g_d0_g0l0v1_977951a22a8026ea8d079c9014c544ba}
```