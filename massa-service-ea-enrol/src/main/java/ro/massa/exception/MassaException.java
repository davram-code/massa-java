package ro.massa.exception;

public class MassaException extends Exception{
    String msg;
    Exception ex;

    public MassaException(String msg, Exception originalException)
    {
        this.msg = msg;
        this.ex = originalException;
    }

    @Override
    public String getMessage() {
        if(ex != null)
        {
            return this.msg + "[" + ex.getMessage() + "]";
        }
        else
        {
            return this.msg;
        }

    }
}