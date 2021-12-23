package ro.massa.exception;

public class DecodeException extends MassaException{
    public DecodeException(String msg, Exception originalException) {
        super(msg, originalException);
    }
}
