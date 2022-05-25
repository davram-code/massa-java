package ro.massa.exception;

public class MassaException extends Exception{
    String msg;
    Exception ex;

    public MassaException(String msg, Exception originalException)
    {
        this.msg = msg;
        this.ex = originalException;
    }

    public MassaException(String msg)
    {
        this.msg = msg;
        this.ex = null;
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
