import hmac
from base64 import b64encode as _b64encode
from binascii import b2a_hex
from hashlib import sha1
from random import randint
from struct import pack
from string import ascii_letters, digits

LIMIT = 0xFFFFFFFF
EMPTY_bSTR = "".encode("latin-1")

BASE_64_ALT_CHARS = "./"
ALLOWED_CHARS = ascii_letters + digits + BASE_64_ALT_CHARS


def b64encode(data, alt_chars=BASE_64_ALT_CHARS.encode("utf-8")):
    return _b64encode(data, alt_chars).decode("utf-8")


class PBKDF2:
    """
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
        self, passphrase, salt, iterations=1000, digest_module=sha1, mac_module=hmac
    ):
        self.__mac_module = mac_module
        self.__digest_module = digest_module

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

        self.__passphrase = passphrase
        self.__salt = salt
        self.__iterations = iterations
        self.__prf = self._pseudorandom
        self.__block_number = 0
        self.__buffer = EMPTY_bSTR
        self.closed = False

    def _pseudorandom(self, key, msg):
        """Pseudorandom function.  e.g. HMAC-SHA1"""
        return self.__mac_module.new(
            key=key, msg=msg, digestmod=self.__digest_module
        ).digest()

    def read(self, bytes_):
        """Read the specified number of key bytes."""
        if self.closed:
            raise ValueError("file-like object is closed")

        size = len(self.__buffer)
        blocks = [self.__buffer]
        i = self.__block_number

        while size < bytes_:
            i += 1
            if i > LIMIT or i < 1:
                # We could return "" here, but
                raise OverflowError("derived key too long")
            block = self.__f(i)
            blocks.append(block)
            size += len(block)

        buf = EMPTY_bSTR.join(blocks)
        retval = buf[:bytes_]
        self.__buffer = buf[bytes_:]
        self.__block_number = i
        return retval

    def __f(self, i: int) -> bytes:
        if i < 1:
            raise ValueError("i must be at least 1")

        if i > LIMIT:
            raise OverflowError("i too large")

        u = self.__prf(self.__passphrase, self.__salt + pack("!L", i))
        result = u

        for j in range(2, 1 + self.__iterations):
            u = self.__prf(self.__passphrase, u)
            result = bytes(x ^ y for (x, y) in zip(result, u))
        return result

    def read_hex(self, octets):
        """Read the specified number of octets. Return them as hexadecimal.
        Note that len(obj.read_hex(n)) == 2*n.
        """
        return b2a_hex(self.read(octets)).decode("us-ascii")

    def close(self):
        """Close the stream."""
        if self.closed:
            return

        del self.__passphrase
        del self.__salt
        del self.__iterations
        del self.__prf
        del self.__block_number
        del self.__buffer
        self.closed = True


def crypt(word, salt=None, iterations=None):
    """PBKDF2-based unix crypt(3) replacement.
    The number of iterations specified in the salt overrides the 'iterations'
    parameter.
    The effective hash length is 192 bits.
    """

    # Generate a (pseudo-)random salt if the user hasn't provided one.
    if salt is None:
        salt = _make_salt()

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
        (s_iterations, salt, dummy) = salt.split("$")[2:5]

        converted = int(s_iterations, 16)
        if s_iterations != ("%x" % converted):  # lowercase hex, minimum digits
            raise ValueError("Invalid salt")

        iterations = converted

    if iterations is None:
        iterations = 400

    if iterations < 1:
        raise ValueError("Invalid salt")

    # Make sure the salt matches the allowed character set
    for ch in salt:
        if ch not in ALLOWED_CHARS:
            raise ValueError("Illegal character %r in salt" % (ch,))

    salt = f"$p5k2${iterations:x}${salt}"
    raw_hash = PBKDF2(word, salt, iterations).read(24)
    return salt + "$" + b64encode(raw_hash)


# Add crypt as a static method of the PBKDF2 class
# This makes it easier to do "from PBKDF2 import PBKDF2" and still use
# crypt.
PBKDF2.crypt = staticmethod(crypt)


def _make_salt():
    """Return a 48-bit pseudorandom salt for crypt().
    This function is not suitable for generating cryptographic secrets.
    """
    binary_salt = EMPTY_bSTR.join(pack("@H", randint(0, 0xFFFF)) for _ in range(3))
    return b64encode(binary_salt)
