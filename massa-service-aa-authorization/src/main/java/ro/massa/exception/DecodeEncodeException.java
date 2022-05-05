package ro.massa.exception;

public class DecodeEncodeException extends MassaException{
    public DecodeEncodeException(String msg, Exception originalException) {
        super(msg, originalException);
    }
}
