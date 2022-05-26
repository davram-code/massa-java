package ro.massa.crypto.client.models;

public class EciesEncryptedKey {
    private byte[] ephemeralPublicKey;
    private byte[] encryptedKey;
    private byte[] authTag;

    public EciesEncryptedKey(byte[] ephemeralPublicKey, byte[] encryptedKey, byte[] authTag) {
        this.ephemeralPublicKey = ephemeralPublicKey;
        this.encryptedKey = encryptedKey;
        this.authTag = authTag;
    }

    public byte[] getEphemeralPublicKey() {
        return ephemeralPublicKey;
    }

    public byte[] getEncryptedKey() {
        return encryptedKey;
    }

    public byte[] getAuthTag() {
        return authTag;
    }
}