package ro.massa.service.impl;


import org.springframework.stereotype.Component;
import ro.massa.common.MassaLog;
import ro.massa.common.MassaLogFactory;
import ro.massa.service.MassaDcService;

import java.io.File;
import java.nio.file.Files;

@Component
public class MassaDcServiceImpl implements MassaDcService {
    MassaLog log = MassaLogFactory.getLog(MassaDcServiceImpl.class);

    private static byte[] getByteArray(String fileName) throws Exception {
        File fin = new File(fileName);
        return Files.readAllBytes(fin.toPath());
    }

    @Override
    public byte[] getCTL() {
        try{
            log.log("returning CTL");
            return getByteArray("../massa-root-ca/certificates/services/ca/ctl.bin");
        }
        catch (Exception e)
        {
            log.error(e.getMessage());
            return null;
        }
    }

    @Override
    public byte[] getCRL() {
        try{
            return getByteArray("../massa-root-ca/certificates/services/ca/crl.bin");
        }
        catch (Exception e)
        {
            log.error(e.getMessage());
            return null;
        }
    }


}
