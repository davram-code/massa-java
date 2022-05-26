package ro.massa.crypto.exception;

public class NotImplementedException extends Exception{

    public NotImplementedException() {
        super();
    }

    public NotImplementedException(String message) {
        super("Function not implemented: " + message);
    }
}
