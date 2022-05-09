from pbkdf2 import crypt, PBKDF2


def test_crypt():
    assert crypt("password", "salt", iterations=1000) == '$p5k2$3e8$salt$lL5MZNjANEQNaCsKXCNKhWXv.eve/YxL'


def test_class():
    i = 1024

    p = PBKDF2("password", "salt", iterations=1000)

    with open('hex') as f:
        assert p.read_hex(i) == f.read()

    with open('bytes', 'rb') as f:
        assert p.read(i) == f.read(i)

