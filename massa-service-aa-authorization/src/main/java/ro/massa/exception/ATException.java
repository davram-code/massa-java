package ro.massa.exception;

public class ATException extends MassaException{
    public ATException(String msg, Exception originalException) {
        super(msg, originalException);
    }
}