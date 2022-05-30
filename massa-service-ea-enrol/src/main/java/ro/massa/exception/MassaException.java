package ro.massa.exception;

public class MassaException extends Exception {
    String msg;
    Exception ex;
    MassaExceptionType type;

    public MassaException(String msg, Exception originalException, MassaExceptionType type) {
        this.msg = msg;
        this.ex = originalException;
        this.type = type;
    }

    public MassaException(String msg, Exception originalException) {
        this(msg, originalException, MassaExceptionType.Default);
    }

    public MassaException(String msg, MassaExceptionType type) {
        this(msg, null, type);
    }

    public MassaException(String msg) {
        this(msg, null, MassaExceptionType.Default);
    }

    @Override
    public String getMessage() {
        if (ex != null) {
            return this.msg + "[" + ex.getMessage() + "]";
        } else {
            return this.msg;
        }
    }

    public MassaExceptionType getType() {
        return type;
    }
}
