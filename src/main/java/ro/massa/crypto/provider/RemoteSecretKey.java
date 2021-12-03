package ro.massa;
import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

public class RemoteSecretKey implements SecretKey {
        public RemoteSecretKey(final byte[] encoded) {
        }

        public RemoteSecretKey(final int shift) {
        }

        public String getAlgorithm() {
            return "ECDSA";
        }

        public String getFormat() {
            return "ECDSA";
        }

        public byte[] getEncoded() {
            return "Not implemented!".getBytes(StandardCharsets.UTF_8);
        }

}
