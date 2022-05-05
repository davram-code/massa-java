package ro.massa.exception;

public class DbException extends MassaException{
    public DbException(String msg) {
        super(msg, null);
    }

    public DbException(String msg, Exception e) {
        super(msg, e);
    }
}