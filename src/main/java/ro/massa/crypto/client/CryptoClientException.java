package ro.massa.crypto.client;

public class CryptoClientException extends Exception{
    int httpCode = 0;

    public CryptoClientException(String message) {
        super(message);
    }

    public CryptoClientException(String message, int code) {
        super(message);
        this.httpCode = code;
    }

}
