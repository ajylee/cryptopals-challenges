
import Crypto.Random
from Crypto.Util.strxor import strxor
from hash_more import SHA1
import hash_auth


def test_SHA1_keyed_MAC():
    random_io = Crypto.Random.new()

    key = random_io.read(16)
    message = random_io.read(300)

    auth = hash_auth.SHA1_Keyed_MAC(key)
    m = auth.MAC(message)

    assert auth.authentic(m, message)

    tampered_message = message[:20] + strxor(message[21], 'x') + message[22:]

    assert not auth.authentic(m, tampered_message)

    fake_key = strxor(key, (len(key) - 1) * chr(0) + chr(10))
    fake_MAC = hash_auth.SHA1_Keyed_MAC(fake_key).MAC(message)

    assert not auth.authentic(fake_MAC, message)
    assert not auth.authentic(fake_MAC, tampered_message)

