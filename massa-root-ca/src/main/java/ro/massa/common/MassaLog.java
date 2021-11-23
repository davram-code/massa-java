package ro.massa.common;

import org.apache.commons.logging.Log;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorization.InnerAtRequest;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.EtsiTs103097DataEncryptedUnicast;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.RequestVerifyResult;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;

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

    public void warn(String msg)
    {
        this.log.warn(prefix + msg);
    }

    public void error(String msg)
    {
        this.log.error(prefix + msg);
    }

}
