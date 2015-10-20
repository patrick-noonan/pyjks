import pytest
from jks.jks import SecretKey
import datetime
from jks import jks

def to_hex(buffer):
    """
    Generate a key string that is compatible with the KeyStore explorer for easy comparison
    :param buffer:
    :return:
    """
    ret = ""
    for byte in buffer:
        ret += "%02X" % byte
    return ret

@pytest.mark.incremental
class Testjks:
    def test_jceks(self):
        """
        Test expected results from a generated key store
        keytool -genseckey -keystore aes-keystore.jck -storetype jceks -storepass mystorepass -keyalg AES -keysize 256 -alias jceksaes -keypass mykeypass
        """
        expected_secret_keys = {"jceksaes": SecretKey("jceksaes", 1445377499510, "AES", 256,
                                                "8EA44C7E9C4923D9D887B2FE66C44977742B2B90BAEAC26EFB4B5680455A012E")}

        ks = jks.KeyStore.load("aes-keystore.jck", "mystorepass", "mykeypass")
        for sk in ks.secret_keys:
            print("\n\nSecret key: %s" % sk.alias)
            print("Timestamp: %s" % datetime.datetime.fromtimestamp(sk.timestamp / 1000.0).strftime(
                '%Y-%m-%d %H:%M:%S'))
            print("Algo     : %s" % sk.algo)
            print("Size     : %d" % sk.size)
            print("Key      : %s" % to_hex(sk.key))

            assert (expected_secret_keys[sk.alias].alias == sk.alias)
            assert (expected_secret_keys[sk.alias].timestamp == sk.timestamp)
            assert (expected_secret_keys[sk.alias].algo == sk.algo)
            assert (expected_secret_keys[sk.alias].size == sk.size)
            assert (expected_secret_keys[sk.alias].key == to_hex(sk.key))
