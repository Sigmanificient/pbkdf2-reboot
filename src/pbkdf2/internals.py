__version__ = "1.3"
__all__ = ["PBKDF2", "crypt"]

import hmac as HMAC
from base64 import b64encode as _b64encode
from binascii import b2a_hex as _b2a_hex
from hashlib import sha1 as SHA1
from random import randint
from struct import pack


_0xffffffffL = 0xFFFFFFFF


def b64encode(data, chars="+/"):
    if isinstance(chars, str):
        return _b64encode(data, chars.encode("utf-8")).decode("utf-8")
    else:
        return _b64encode(data, chars)


class PBKDF2(object):
    """PBKDF2.py : PKCS#5 v2.0 Password-Based Key Derivation
    This implementation takes a passphrase and a salt (and optionally an
    iteration count, a digest module, and a MAC module) and provides a
    file-like object from which an arbitrarily-sized key can be read.
    If the passphrase and/or salt are unicode objects, they are encoded as
    UTF-8 before they are processed.
    The idea behind PBKDF2 is to derive a cryptographic key from a
    passphrase and a salt.
    PBKDF2 may also be used as a strong salted password hash.  The
    'crypt' function is provided for that purpose.
    Remember: Keys generated using PBKDF2 are only as strong as the
    passphrases they are derived from.
    """

    def __init__(
        self, passphrase, salt, iterations=1000, digestmodule=SHA1, macmodule=HMAC
    ):
        self.__macmodule = macmodule
        self.__digestmodule = digestmodule
        self._setup(passphrase, salt, iterations, self._pseudorandom)

    def _pseudorandom(self, key, msg):
        """Pseudorandom function.  e.g. HMAC-SHA1"""
        return self.__macmodule.new(
            key=key, msg=msg, digestmod=self.__digestmodule
        ).digest()

    def read(self, bytes):
        """Read the specified number of key bytes."""
        if self.closed:
            raise ValueError("file-like object is closed")

        size = len(self.__buf)
        blocks = [self.__buf]
        i = self.__blockNum
        while size < bytes:
            i += 1
            if i > _0xffffffffL or i < 1:
                # We could return "" here, but
                raise OverflowError("derived key too long")
            block = self.__f(i)
            blocks.append(block)
            size += len(block)
        buf = "".encode("latin-1").join(blocks)
        retval = buf[:bytes]
        self.__buf = buf[bytes:]
        self.__blockNum = i
        return retval

    def __f(self, i):
        # i must fit within 32 bits
        assert 1 <= i <= _0xffffffffL
        U = self.__prf(self.__passphrase, self.__salt + pack("!L", i))
        result = U
        for j in range(2, 1 + self.__iterations):
            U = self.__prf(self.__passphrase, U)
            result = bytes([x ^ y for (x, y) in zip(result, U)])
        return result

    def hexread(self, octets):
        """Read the specified number of octets. Return them as hexadecimal.
        Note that len(obj.hexread(n)) == 2*n.
        """
        return _b2a_hex(self.read(octets)).decode("us-ascii")

    def _setup(self, passphrase, salt, iterations, prf):
        # Sanity checks:

        # passphrase and salt must be str or unicode (in the latter
        # case, we convert to UTF-8)
        if isinstance(passphrase, str):
            passphrase = passphrase.encode("UTF-8")
        elif not isinstance(passphrase, bytes):
            raise TypeError("passphrase must be str or unicode")
        if isinstance(salt, str):
            salt = salt.encode("UTF-8")
        elif not isinstance(salt, bytes):
            raise TypeError("salt must be str or unicode")

        # iterations must be an integer >= 1
        if not isinstance(iterations, int):
            raise TypeError("iterations must be an integer")
        if iterations < 1:
            raise ValueError("iterations must be at least 1")

        # prf must be callable
        if not callable(prf):
            raise TypeError("prf must be callable")

        self.__passphrase = passphrase
        self.__salt = salt
        self.__iterations = iterations
        self.__prf = prf
        self.__blockNum = 0
        self.__buf = "".encode("latin-1")
        self.closed = False

    def close(self):
        """Close the stream."""
        if not self.closed:
            del self.__passphrase
            del self.__salt
            del self.__iterations
            del self.__prf
            del self.__blockNum
            del self.__buf
            self.closed = True


def crypt(word, salt=None, iterations=None):
    """PBKDF2-based unix crypt(3) replacement.
    The number of iterations specified in the salt overrides the 'iterations'
    parameter.
    The effective hash length is 192 bits.
    """

    # Generate a (pseudo-)random salt if the user hasn't provided one.
    if salt is None:
        salt = _makesalt()

    # salt must be a string or the us-ascii subset of unicode
    if isinstance(salt, str):
        salt = salt.encode("us-ascii").decode("us-ascii")
    elif isinstance(salt, bytes):
        salt = salt.decode("us-ascii")
    else:
        raise TypeError("salt must be a string")

    # word must be a string or unicode (in the latter case, we convert to UTF-8)
    if isinstance(word, str):
        word = word.encode("UTF-8")
    elif not isinstance(word, bytes):
        raise TypeError("word must be a string or unicode")

    # Try to extract the real salt and iteration count from the salt
    if salt.startswith("$p5k2$"):
        (iterations, salt, dummy) = salt.split("$")[2:5]
        if iterations == "":
            iterations = 400
        else:
            converted = int(iterations, 16)
            if iterations != "%x" % converted:  # lowercase hex, minimum digits
                raise ValueError("Invalid salt")
            iterations = converted
            if not (iterations >= 1):
                raise ValueError("Invalid salt")

    # Make sure the salt matches the allowed character set
    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./"
    for ch in salt:
        if ch not in allowed:
            raise ValueError("Illegal character %r in salt" % (ch,))

    if iterations is None or iterations == 400:
        iterations = 400
        salt = "$p5k2$$" + salt
    else:
        salt = "$p5k2$%x$%s" % (iterations, salt)
    rawhash = PBKDF2(word, salt, iterations).read(24)
    return salt + "$" + b64encode(rawhash, "./")


# Add crypt as a static method of the PBKDF2 class
# This makes it easier to do "from PBKDF2 import PBKDF2" and still use
# crypt.
PBKDF2.crypt = staticmethod(crypt)


def _makesalt():
    """Return a 48-bit pseudorandom salt for crypt().
    This function is not suitable for generating cryptographic secrets.
    """
    binarysalt = "".encode("latin-1").join([pack("@H", randint(0, 0xFFFF)) for i in range(3)])
    return b64encode(binarysalt, "./")
