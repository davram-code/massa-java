package ro.massa.common;

import org.apache.commons.logging.Log;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.EtsiTs103097DataEncryptedUnicast;

public class MassaLog{
    Log log;
    String prefix = "[MASSA]\t";

    public MassaLog(Log log)
    {
        this.log =  log;
    }

    public void log(String msg)
    {
        this.log.info(prefix + msg);
    }

    public void log(String description, EtsiTs103097DataEncryptedUnicast dataEncryptedUnicast)
    {
        this.log.info(prefix + description + dataEncryptedUnicast.toString());
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
