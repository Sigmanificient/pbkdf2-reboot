# PBKDF2 reboot

[![codecov](https://codecov.io/gh/Sigmanificient/pbkdf2-reboot/branch/main/graph/badge.svg?token=OP0X4ZR5JZ)](https://codecov.io/gh/Sigmanificient/pbkdf2-reboot)

A modern Python 3 library for PBKDF2 password hashing.

The library code is derived from the original Python 2 library [python-pbkdf2](https://github.com/dlitz/python-pbkdf2) 
that hasn't been updated for 11 years.
The main purpose of this library is to provide a more in-time version with typing support.

## Usage

```py
>>> from pbkdf2 import crypt
>>> pbkdf2.crypt('password', 'salt', iterations=1000)
'$p5k2$3e8$salt$8U24fPYH1KBtWqbN5ibra6gQR2ZV864RD1qpxeEVv/Q='
```

```py
>>> from hashlib import sha3_512
>>> from pbkdf2 import PBKDF2
>>> p = PBKDF2('password', 'salt', iterations=1000, digest_module=sha3_512)
>>> p.read_hex(64)
'e697001cf40fe4623eb67df2ddab791a499451234957133097deffce766fc9839e4642de2a1cfea8307d98bde6995bab8cf70453dc8eab92fcba0a02a2ae026e'
```

