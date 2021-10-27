package ro.massa.common;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class MassaLogFactory {
    public static MassaLog getLog(Class<?> clazz)
    {
        Log log = LogFactory.getLog(clazz);
        return new MassaLog(log);
    }
}
