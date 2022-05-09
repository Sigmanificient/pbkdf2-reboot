import pytest
from pbkdf2 import crypt, PBKDF2

HEX = (
    '6e88be8bad7eae9d9e10aa061224034fed48d03fcbad968b56006784539d5214ce970d912ec2049b04231d47c2eb88506945b26b2325e6adfe'
    'eba08895ff9587a30b79968d7c300921db460902c9e1838b09462351a549a1f1d84e47a4e521b839224cf347c3a09ea223e344955cd659813e'
    '6a80ef11fda1ca2b5749311501bac5d99474b3725ff440dc71deac3ff80a20748911a1d55a5de4283a7820da3a21015fd5721b3adada046620'
    'c9e88b45b96a95dc319ab0304245779cc7fd69794dc8312ad9073682a727f11d7a2791cdb15bf89ab701da1389be1e76e8004d1cd0f693ad1e'
    '968dd49c121451c139429ae7a287ea791ea592cb9cf725ce2a3fbb7763f1913488f9ab99930e6832c3c615fc4d63608355059aecec4490197d'
    'b6bd09063bcaa5aeca472bd1070db2b14b7d231e163c0c1d0595f98923f1daf96ec451d287c351710c11c50c326c37a34df80200303657315f'
    '732caa1d1a688ccb52dde76b6beb653bf4cdfb3d37c6c38cc34a214f7ff2c12a45ed2e5f2057a91927ff72e6bf0786c01176e92909def40c30'
    '4b08695e86955f3e3b612fb95fd4447b5bedd178853ca5403589f8cc07ef131b52e8917c96e40a9e2806f25f7c88e5e62d09bd857478d25898'
    'a739eb7347b78f5f572b6545352be2c17c84669e3dc30399a07abd75399de4a5818c905b4169573fde8e4b100769277edd48f8535a992493b1'
    'ec54755c07b2eee8f8faaba39bb570ff33fbd498d6d7377dd3592f2f77292cee24da9d75812f3e2bf9529f7c9da28add3320c183cc05c179d8'
    '3f9d06a50d5e06011610a40f2f3b646a3087a0a06e6e6a24ba8f89aab4d2d65a23055e4e6083f65d7e13a8fe18ecc29e1e1b188b7a8a553c17'
    'd98599e6fe61865a07746e54dea244b99f94a5a5210bc00f7a4236f800f56d25cad67b36ab39dd36e1c4f0f2f3d067df009cb299d610084d33'
    '091711aa51b823f247ed47bc0f1aafd0c95114244fd2c324f2a0d499af5d0b192e4343a64fa909ced0338c774a348aefd777f0cd4f84b12935'
    '0c2698571d401a329d923440fe7ec33ebd6f84429560148e8a44c1a78e504f59e76889671ae59fd9d885c07a4eeb26ded1351c66e72bdb2afc'
    'a0a64118d36283777391f8ec5ef4964379db58d2fabb575dd85a7ddd35f20b15a6164dfdec6536495a4a8435c4e053343fadeac0c08898ca1d'
    '858468c01846fe415ef628b0f3baa593ef7b4b0c629c72ac4f7a399bacf489e52adeaac7ac7c4a5c35ff3b5a063fac05016ae33ce129004c79'
    'fc9afbcdf9011758acd1c644f71710d37a38872f1ff70742f8198f0100401aa9fa438db9c8e50e719ccbde5ba0ae9022f21860d3a620099cee'
    'd0178e7d1503c04ed1484dd99ca4befa6c957af658832aa9184204f8c7e8f7dfb116022604b6060cf40d83e28835a9f3746dcf842bf27a'
)

BYTES = (
    b'\xc7h\xa2\x8c\xedIl\x86\xba\x89\x1a\xbe2\x97\xf5\x93$\x1b^|\xa3`\xdc\x0b\x86\xcf\xdf\xbe\xff2J$\xc8\xa2\x94\x86'
    b'\xe1\xb0\x8e\x0b\x95+oxj\x0c\xb1\xb9\x97\x19\xf8\xa9)]\xb5\xe7\x1b\xa72\xa789\x04\xda\xe0\xd8|\xc3\x8f\xe0T\x10'
    b'\x1cKKN?K\xe1\xed(H/\x1d\xfc\x89;\x8e\xdd(\xa7\tf=\xc6\xeb\xcd\xc9\x88\x00\xecbe\x1d\xbf\xea\xbe\xac\x11\xdb\xaf'
    b'\x0b\xef[\x84\xb7\xbd\x0e\x8ds\xd8\xd7\x0csC\xa9G\xd2\xeeOk\x0c\r&\x03\xab\x17\xb8s\x93\xe9\xf2\x8ey\xa8u2\xc6'
    b'\xd6Yt\xfbN_\xd8\x0b<D8\x1bJ#O\x88\x13V\xf6\xc1k\x91\x16S\x9d\xe62i\x98D\xc25\xdf\x15\xb6\x1b"vc\xd5\x1dx\xc3\xf4'
    b'\x17\xad\x05\xf7"]\xb3KL\x97e\xda\x1d\x1d+\x926s.J|\xe9J^=8\xec7\xfd\xfeY<B#\xf7\x90\x9eE\x84\xe7\x88\xc6\xc2\xba'
    b'\xa1|u\xeb\x0f-\x0c\x14V5\xc6T^\xb26\xce)7\xa1^\xadK\x9bX\xd6\xc1\xe6\x87\xc3\xf4\xe4=\xfdh\\>\xf9jK\xfc\x90\x97b'
    b'\xbf\x19\xfbK\xc3u:\x0b\xb6\xbdY\x1a\x96\xd1l3qo\x97t\x0euK\x90\xcd%\x93\xf2\x97\xdc\xdc\x97\xfa\xa9\x90\xb2\xf1'
    b'\x94:P\xb3q\x97\x18n5\xc9\xf5\r\rK\xa3\x0f\x12\xabz\xf3\xa8\xc8\x975\xf3\xa9G!\xbd\x19\x08\x17\xfd\xffAi\x8c{&y'
    b'\x98\x10\xc3\xf7\xe7\x80\xb3\xcb\xb9\xaa\x86\x96\xe6\x8b\xa9\xa7h\x92\xf8\x13\xbc<G\xca\r\xfa\x9a\x90\x0c\x99\x8e'
    b'\x14|\x80^\x9fA\x877\xa0o\x82\x18u\xf20kE\x80\xd5N\xb5\x1c\xdb\xf9\xc30\xbe\t`v\xb9\x9e\x01\x14\x10\x04\n\xb9'
    b'\x8a[\x15\xa5\x02\x84\xe7F\x0b*+\xbb\xb0\x9a\x1dv\xf9\x7f\xc1\tS\xba\n@\xc4\x19\x14@C\x880\x8e\xd7;\xad\x8a\xa9'
    b'\xd1\xb4\xc3\xda\xa3/\xf4q\x9d2i\xeaZ\x82l\xf6\x94\xf3EtU\xe3[f\xc7\xd3\xfc!\xac )\x80g\xf6\xd9-4\xfavM\x16%g'
    b'\x84]\x98>\x9e1\x81]\xb1\x8b\x0c\x05\xf2b\xa9\x837\x8b\xc0n\xa28\xe9"=\x08!\xd1\xac\xb2~7\xc5\x88\xa8u^TMr\x99'
    b'\xe0G@Y\x01\xf0\xb9\xfeI@\x93\x92\xab`\x01N\x1bY\x16\xa0\xfe\xe3\xd8\xb6\xf5\xd1\x98pNp\xb0,\xe6\xf76\xd3\xf6&'
    b'\xe2\xc4$n5\x12])d\x0c\xf3\x9e&a\xfd\xe7\xe5)\x86+)\xceQD\x18wNW\x88R1\xa6\xc2\xc0p\xb9/\x81n^8\xfd\xfec0l\xb1'
    b'\x8cTL\x1b@\x8e\xb6\xb5>\xdb\xf4\xca0\xb9\x8b\xb7$!\x7f\x000B\xaa\xc8\x02\xc2pa\xe4q\xd8D"p6Y\xea\xa5\xfa\xb0X'
    b'\xde\xad\x0b?\xdd\xe5\xad\x16\t\x82\xa9\x93\x8f\xcag\x16\x8c\xcfk\xeb\x92!\x0c\xe5\xa9\xe5\x9c\xc5\xd7\x96@\x9em"'
    b'\xa3o\xea\xbfZ\xdc\r\x00\xc6\x01l\xb2\xde\xd6\x85g2^\x8c%\x9c\xce\x9d\x01\xdf\xee\xc9U~\xd4\xfd\xa7\xd4\xe5\xd6[G'
    b'\xdc\x08#_\ny\\8\x1b7?\x1b\xe5\xac+x#6\x8b@j\xeaM\xc2\x19 \xec\x9a0\x82\xddFl\xc6W\xa6\xf57\xd3W\xebw\xb2y\xa5o'
    b'\xf9\x96\xad\xa9\xfbp\xbf\xc5j\x1d\xaby\xd7/\xb5\xf6\x1f\x1e\xaa\x8d\xea\x87kWc\x82d\x11H$S\x03\x0c\xa7\xcd\xa7'
    b'\x97\xa8\xa7\xd4\xd6_s\x94\rH\xe6\xa7E\xf6s`\x9f\x90e\xff\x7f\xea\xb4\xc95\xeb\xff\x92\xc2G{\xdc\xc1#\x1cZ&\x80w/'
    b'\x10k\xd4+\x0c\xb1;\xb2\x03K\xd0#\xca\xbfe\'LIE.\xa6)\x12\xcaz{\'\x93)I\xc5g-\x8b(r\xa1\xd0\x99\x9e;K\xe4\xc7J@'
    b'\x00X\xe0\xad\xb25d\x10\xd83\xea\x1at\xd6\xa7\xdft\xa2\x8b\xc8\x84\xb1\x0c\x91\xbc\x94\x15s\xb9\x88\xdfi\x0c\xb3'
    b'\xc6\xdaa\xe9\n\x1a\xb5\xbc\xf9\xbb\t\x97&kfk\xf3\xe1\xa7\x9fm7\x83\xdb\xc7\x87\xe1\x0cg\xca\x19\xde\x05\x85'
    b'\xe0}#\x02Y\x13\xe5\xfc{\x9a{V\x89\xd7\xa7%N\xa3\xc3\xb4\x11\x82\x9c\xd0\xa9`4\x8e\x8c\xd6\xf5\x19&\xb5i\x1aer.'
    b'\xf5PC\xdd\xa0^'
)


def test_crypt():
    assert crypt("password", "salt", iterations=1000) == '$p5k2$3e8$salt$lL5MZNjANEQNaCsKXCNKhWXv.eve/YxL'


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
        _ = PBKDF2("password0", "salt", iterations='')

    with pytest.raises(ValueError):
        _ = PBKDF2("password0", "salt", iterations=0)

    with pytest.raises(ValueError):
        crypt('password', 'salt-')

    with pytest.raises(TypeError):
        crypt(1, 'salt')

    with pytest.raises(TypeError):
        crypt('password', 1)


def test_no_salt():
    c = crypt("password")
    assert len(c) == 48
    assert c.startswith('$p5k2$$')


def test_close():
    p = PBKDF2("password", "salt", iterations=1000)
    p.close()

    assert p.closed


@pytest.mark.skip(reason="too long")
def test_overflow():
    p = PBKDF2("password", "salt", iterations=1)

    with pytest.raises(OverflowError):
        p.read(1 << 32)
