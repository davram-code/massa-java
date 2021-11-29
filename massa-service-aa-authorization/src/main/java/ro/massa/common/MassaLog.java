package ro.massa.common;

import org.apache.commons.logging.Log;
import ro.massa.properties.MassaProperties;

public class MassaLog{
    Log log;
    String prefix;

    public MassaLog(Log log)
    {
        this.log =  log;
        try{
            prefix = "[" + MassaProperties.getInstance().getLogPrefix() + "]\t";
        }
        catch (Exception e)
        {
            prefix = "[MASSA]\t";
        }
    }

    public void log(String msg)
    {
        this.log.info(prefix + msg);
    }

    public void warn(String msg)
    {
        this.log.warn(prefix + msg);
    }

    public void error(String msg)
    {
        this.log.error(prefix + msg);
    }

}
