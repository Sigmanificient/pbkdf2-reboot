import pytest
from pbkdf2 import crypt, PBKDF2

HEX = (
    "632c2812e46d4604102ba7618e9d6d7d2f8128f6266b4a03264d2a0460b7dcb388b3b1131f741bcbeb02541c8c2e97bd8bed62ab6425542e45"
    "512b7312f440ebc6e21f4356a5edf32cf0394e0d5be940e0e930cfe21e38a3ff94e28d26c23fac7701ac92f52ade33aad5663b057526d66c32"
    "f2239c65e5510f3bb57cb914f1e0e051605dce56d911c8ddfcea6105cb8f2fa3a498869755684b795bd72bfc63bca27020c5b81cb2adaf3e16"
    "435b6d20d1fd1446902511e7a8a25aa7dfaf115a62ecbfc63656ac3de0a23c1aa3c25c88ed1977080ce2d708cf010881038afa103097e44444"
    "cb014d9fd4971c69a8d4ca1e2e28af068b7f7149a167da64d066727a8f815f430b7c4023bbcf6a3b4ec5a1f400d2591a884eda4e4b23354602"
    "21d3f2ba880518da245762ce92a5c754c8ca05edca8ffa6e7749695252fda38f124951e150d241d4c25a8df300c2d962f9411a5563b87e6232"
    "08587c613f3ff88a06926ec202ded66891c74d8f3b49690576f27ca67c77117a278c543b3dfc353f94e5e0f41a149705c08b9d85eb473679bf"
    "a5d80dfb6c494bd6a16c7783fd5bf34b8eadc7158c1c645cd877ea6bada8b55ceaa34d114567fdc3e034b6134f73dcc5670ae10790b989a6d7"
    "f33b2aa60e269ba7c8b10e7ffb841076f98cd268ffeaff7defa3fe1d9a2f3c14dca4df926242e053e32dd9fe46f3835eaba3c78714b59d7fa5"
    "a96bde5ab52831c654282d55feef180ed6bcb58b1cd74757417eb272aab0a47237b3b7b94e1a59558e43ec7006af11c9dfc3175775ac6c2978"
    "349cbf510ec49854c0e96defc027957fa2245071dab449a119e040728b396e4aa2c292cabde2bd4991d77940f93ade5870d673e40a5ad87643"
    "8c30335fa13344b08f3c8f9425f0ca405de9e4cea0feb50cf8423eaea61fb93d7d4518102bf7fb332f2f141775a10ce445cb58b8fee59e4303"
    "a68c30afb48dcc1d33ef3dacf1320ea6d18b29f7aeb58b2f9a9e86e6df5212b376a082db563890810a3117dd67e78c22cca30717cf5d76224b"
    "bb2d30d439956699076455f68279e4fdad86859cdb146952e60eba9c05bcda5c72d8a3dd48196bca351f666d69a6ecca2cf9e4e12d0df50df0"
    "32a08bc04471de4c875607055ed3ffc6a251cf5787c63e0276f09a99c0a33c8abd96b732d844176a3f40dbcfdba074606afdbbc38c62481a97"
    "d9d8b7ddde41c8f6920ff48f8db81d96365df12157362f51aaae0c1068c8edc367e1c8011b6473978541b7dff61cb385f10fc219d58eaf3dd3"
    "493c671ce67e56dd38ef4f0314e4dc4833f5589c342b230a55d2439dbc1034ebe58e9edd75f051c56950142334375103d51ec48fc6e8320d7a"
    "c402a3505a64a05e738068fe126874eb603e52e17864b38ab9aa98f75afa08a4b91783e4f5c6b7bfb81009aa4c41b47052996469a46e91"
)
BYTES = (
    b"\xf2fnu\x10\x1bB\xce\xbf\x9f\xb8e\xd3$\xa0-\tbG>\xd6\xbb\xd0$Ih\x18\xa9"
    b"\xbbCm\xb7`k\xb8\x98Cp7\xd8\xack\xfb\xa1\xb2w5,l\xa8\xbb\xeb\x8c$Q\xbe"
    b"\x18\x94\xfb}M\xbc<\xab9\xdc\xc3:\xd2>[+\x96\x91\t\x16B\x9b\xcf1\x04|\x036"
    b"?2S9\x85$\xfa\x87\xe2Ul\x85\x9d\xaa\x9f\xadC;\xafZ\xae\xd8\xc7\xde"
    b"\t\xa4d\x867\xd8\x9d\x87\xa6\x1f\x13\x1dXa\xf87N\xb6\xc7/\xd0=<\xbe"
    b'\xe4\t\x93\xc4\xae\xe1"B\xccFh\tx\x8dEQ\xbc=\xd6\x1c@\x95!]\xb4\x8dL1'
    b"\x0bI\xd9\xad\xd2\x02}e\x05w.\xc4\xfe\xd0\xea\x8c\xc8S\x87_d1b\xab\x06J1k"
    b"\xf7*\x18d\x10\xd6\xa8\xd5[m%\xe1\xd5\\\x01\x97\x15\xd5(-.\xcd\xfe\xa3"
    b"&\xbe\x7f\x0f\xc8H\x08c\xfc\x8d?\x9d\xb1\xdeg\x12\x05\xd3\xf2`"
    b"\x9d\xfc\x0b\xf0\xee\x07\x1c\x078\xd86\t\xd90\xae\xac\xce\xc9\xd9B"
    b'\x0f\x92\xd5v\xb4" \xd0?Z\xf3\xaf\xd7U\xf3\xdc\x8a:\x17\xcd\x89\xdf\r\x1a'
    b'\xb2"]\xdb\x14\x96\xa9y\x93\x9e\xf3H\xfa\x07\x11t\x96\x95\xac\x06\t~\x96\xef'
    b"\xecB\xbex\x9d\xb9\x90\x04s\x9b\x84\xc4\xe1\xa2\xa6%\r^\xcb_F\xaa\x8d\xb9"
    b"\xcb\x06\xbe\xd5$\xea\xde\xcc\xf1e\x1f\xe6\x07\xd3\xdd\x84\xa1\x7fo\xae"
    b"\xe6E\xed\x8f\xafs`\x06\x8b\xe7\xe7l\xad\xff\x8b8\x0e\xa6\x0e[\x06A\xe9\x13"
    b"\x9a\x93\xf6\xe78k\xadq\xe2\x07Y2\x96\xda@US\x89x\x942\x8c~\xe8V\xd0\x86\xe2"
    b"'\xd7.I\xc6\xae\x15NX\tl\x9b\x02\xfc\x85\xe5\x03\xe5\xb2\xe8\xae\xe5\xc1\x8e"
    b"\xebyS\xff\x8d,\xc5\xe9\xa0\xbe$I+iO\x8bR\x9alL_\xd8\x0b\r9\x8d\xd1W"
    b"y\xb3\xc7Zn,\x8e^'\te?&\xc6r\x07\x00\x8f\xfa\xfcci\xf1?+$\xc8\xb6"
    b'\xc0\x0e\x1c\x0e\x18}>"\x8f\xee\xae!mv\xdd/\xbc\x12M\x03\x86G\xfa\x90'
    b"n\xac\xccX\xfb\xc3y\x94\xa0\xf2\x0cl\xb3\xdf\xb1\xb3\xd2h\x87Zb\xa6\xcal"
    b"!k\xdc7@\x0bV\x14C[\xae0\x1d\x11\x85\xbc\x98\xaa\xb4\x8e\x1c\x88\xdf\x91"
    b"\xba{\xd1g\xd8\xfeG\xe1vv\x03\x13V\xc6\xe4Y1\xae%\x8a\xed{\xca\x9b"
    b"\xd5\x84\x1b\xf4\x160\xf6\x9d\xb4\xce\xb8\x99:\xbe\xb9Y\x97\x11&,A\x1c;\xb4"
    b":\xc3\xed\xae\xe8-\x97o \xc9\x04z\xb8\xfa#\xc2\x8e\x86H\xc9%\x9d>\x16\xf0j%="
    b"\x8bC\xba\x90\xd4c\xa1Ow\t\xfdr\x90\xf0\xfea\xeb\xa7\x90\xab=X\xbd\xe3"
    b"\xb7\xbbp0\xdd\x83\xeaVCt\xe3 mD\xeda\x12;s\xe2\xd6\x88#2\x0e\xf1j\xbb"
    b"\xf1\xad\xbb\x91\xec\xce\xc2p>7>\xe1*\xf8\x8f\x16g\xa8\x012\xb4\xfa\xcf\x14"
    b"\x8c8s\xdc\x0e-\xff\x88\xa8\xd0b&\x93\x01\xd6>\xbd\x9a\xf0ft\xf3\xcb\xa4"
    b'\xb9\xd6\xd2\x10r\xe2"TB\xdfZ\x1c@!KySJxC<\x946\x99\x11\xa9\xc4\xa3'
    b"\x00\xf0\x0c}\x8b\x1f\xbaM*\x83Q\xb5\x07b\xf7\xc8\x92\x89\xe9\xa4\xebx|\xfc"
    b"{\x9f\xe9\x05\x0cr4\xe0\x06&\xb3\x9b_I\x9c\xd2\x1f\xb9=\xb6|\x9e\xe9\xa7"
    b":=\xe5\x86\xeb/\x15\xbd\x88\xe3H\x9e\x04\x1cEC)6)^\x8a\xb3\xd0\x84"
    b"\xa58\x90\x03\xe8\xba\xf5Y9*\xc8\xd1\nt\x07\xcc\xf7\xf7\x89\xfa.<\xd9\xf8"
    b"\xf4\xf8\xb6\xf9Q.\x18\xca\xf5\xd4\xae\xd0\xb5\xca|\xf7\xc7\xf9\x15G"
    b"\x82\x1f\x18\x8e\xb5\xfb\x82\x94j\xa8s\nfo\xe9\xa0RH\xa7\x13Kq.W"
    b"\xa5\xd7\xfb\xb2\xe1r\x17*\xf2?\xc1\xb86\x90\x8fv\x90\x1by'Qnk^9&R4"
    b"\x85\x10\xf7)J\xe5\xf1#5\x8f\xc7\xdfN\xc4<\xf3\xac\x04\x16\xb2qS\xc9\xd2"
    b"\xa8v\xb6\xf5\xb2\xe2\xf7V6_~\xc8\x14g\xa13i\x97\x9a_Y\xd1\xe6\xa9"
    b"\xed\x8e*\x95\xe7\xe1D\xf1\x16\xdc`\x1a\xba\x0eU\x9a\xbao\x91o\xaaf\x01`"
    b"*\x17#`\xfa1N\xbc\xb8\x98\xfd0\xe0\xd0\xe3&\x1b\xac\x8bk\xa5\xaf\xcb\xc6"
    b"?\x0e7%\xd4\xa1K\xa3"
)


def test_crypt():
    assert (
        crypt("password", "salt", iterations=1000)
        == "$p5k2$3e8$salt$8U24fPYH1KBtWqbN5ibra6gQR2ZV864RD1qpxeEVv/Q="
    )


def test_class():
    i = 1024

    p = PBKDF2("password", "salt", iterations=1000)

    assert p.read_hex(i) == HEX
    assert p.read(i) == BYTES


def test_errors():
    with pytest.raises(TypeError):
        _ = PBKDF2(1, "salt")

    with pytest.raises(TypeError):
        _ = PBKDF2("password0", 1)

    with pytest.raises(TypeError):
        _ = PBKDF2("password0", "salt", iterations="")

    with pytest.raises(ValueError):
        _ = PBKDF2("password0", "salt", iterations=0)

    with pytest.raises(ValueError):
        crypt("password", "salt-")

    with pytest.raises(TypeError):
        crypt(1, "salt")

    with pytest.raises(TypeError):
        crypt("password", 1)


def test_no_salt():
    c = crypt("password")
    _, algo, iterations, salt, hash_ = c.split("$")

    assert algo == "p5k2"
    assert int(iterations, 16) == 10000
    assert len(salt) == 16
    assert len(hash_) == 44


def test_close():
    p = PBKDF2("password", "salt", iterations=1000)
    p.close()

    assert p.closed


@pytest.mark.skip(reason="too long")
def test_overflow():
    p = PBKDF2("password", "salt", iterations=1)

    with pytest.raises(OverflowError):
        p.read(1 << 32)
