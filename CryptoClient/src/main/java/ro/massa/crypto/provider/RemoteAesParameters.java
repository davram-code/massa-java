package ro.massa.crypto.provider;


import org.bouncycastle.util.Arrays;
import java.security.spec.AlgorithmParameterSpec;

public class RemoteAesParameters implements AlgorithmParameterSpec {
    private byte[] associatedText;
    private byte[] nonce;
    private int macSize;

    /**
     * Base constructor.
     *
     * @param macSize macSize in bits
     * @param nonce nonce to be used
     */
    public RemoteAesParameters(int macSize, byte[] nonce)
    {
        this(macSize, nonce, null);
    }

    /**
     * Base constructor.
     *
     * @param macSize macSize in bits
     * @param nonce nonce to be used
     * @param associatedText initial associated text, if any
     */
    public RemoteAesParameters(int macSize, byte[] nonce, byte[] associatedText)
    {
        this.nonce = Arrays.clone(nonce);
        this.macSize = macSize;
        this.associatedText = Arrays.clone(associatedText);
    }

    public int getMacSize()
    {
        return macSize;
    }

    public byte[] getAssociatedText()
    {
        return Arrays.clone(associatedText);
    }

    public byte[] getNonce()
    {
        return Arrays.clone(nonce);
    }
}
