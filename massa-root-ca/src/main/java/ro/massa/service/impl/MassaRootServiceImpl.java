package ro.massa.service.impl;


import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.springframework.stereotype.Component;
import ro.massa.common.MassaLog;
import ro.massa.common.MassaLogFactory;
import ro.massa.common.Utils;
import ro.massa.its.RootCA;
import ro.massa.service.MassaRootService;

import java.nio.charset.StandardCharsets;

@Component
public class MassaRootServiceImpl implements MassaRootService {
    RootCA rootCA;
    MassaLog log = MassaLogFactory.getLog(MassaRootServiceImpl.class);

    public MassaRootServiceImpl() throws Exception
    {
        log.log("Initializing MASSA Root Service");
        rootCA = new RootCA();
    }

    @Override
    public byte[] getSelfSignedCertificate(){
        log.log("Getting the Self Signed certificate of the Root CA");
        try{
            EtsiTs103097Certificate rootCert = rootCA.getSelfSignedCertificate();
            return rootCert.getEncoded();
        }
        catch (Exception e)
        {

        }

        return "ion".getBytes(StandardCharsets.UTF_8);
    }

    @Override
    public byte[] certifyEnrollmentCA() {
        log.log("Resolving EA Certificate Request");

        try{
            EtsiTs103097Certificate eaCert = rootCA.initEnrollmentCA();
            return eaCert.getEncoded();
        }
        catch (Exception e)
        {

        }

        return "ion".getBytes(StandardCharsets.UTF_8);
    }

    @Override
    public byte[] certifyAuthorizationCA() {
        log.log("Resolving AA Certificate Request");

        try{
            EtsiTs103097Certificate aaCert = rootCA.initAuthorizationCA();
            return aaCert.getEncoded();
        }
        catch (Exception e)
        {

        }


        return "ion".getBytes(StandardCharsets.UTF_8);
    }
}
