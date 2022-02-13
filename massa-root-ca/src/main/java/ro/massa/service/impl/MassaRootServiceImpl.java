package ro.massa.service.impl;


import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.springframework.stereotype.Component;
import ro.massa.common.MassaLog;
import ro.massa.common.MassaLogFactory;
import ro.massa.common.Utils;
import ro.massa.db.DatabaseClient;
import ro.massa.its.RootCA;
import ro.massa.service.MassaRootService;

import java.nio.charset.StandardCharsets;

@Component
public class MassaRootServiceImpl implements MassaRootService {
    RootCA rootCA;
    MassaLog log = MassaLogFactory.getLog(MassaRootServiceImpl.class);

    public MassaRootServiceImpl() {
        log.log("Initializing MASSA Root Service");
        try {
            rootCA = new RootCA();
        } catch (Exception e) {
            log.error(e.getMessage());
        }
    }

    @Override
    public byte[] getSelfSignedCertificate() {
        log.log("Getting the Self Signed certificate of the Root CA");
        try {
            EtsiTs103097Certificate rootCert = rootCA.getSelfSignedCertificate();
            DatabaseClient.database_test(); //TODO: remove this from here
            return rootCert.getEncoded();
        } catch (Exception e) {
            log.error(e.getMessage());
            return e.getMessage().getBytes(StandardCharsets.UTF_8);
        }
    }

    @Override
    public byte[] certifyEnrollmentCA(byte[] request) {
        log.log("Resolving EA Certificate Request");
        try {
            EtsiTs103097Certificate eaCert = rootCA.initEnrollmentCA(request);
            return eaCert.getEncoded();
        } catch (Exception e) {
            log.error("EA Certificate Request Failed!");
            log.error(e.getMessage());
            return e.getMessage().getBytes(StandardCharsets.UTF_8);
        }
    }

    @Override
    public byte[] certifyAuthorizationCA(byte[] request) {
        log.log("Resolving AA Certificate Request");
        try {
            EtsiTs103097Certificate aaCert = rootCA.initAuthorizationCA(request);
            return aaCert.getEncoded();
        } catch (Exception e) {
            log.error("EA Certificate Request Failed!");
            log.error(e.getMessage());
            return e.getMessage().getBytes(StandardCharsets.UTF_8);
        }
    }

    @Override
    public byte[] rekeyAuthorizationCA(byte[] request) {
        log.log("Resolving AA Rekey Certificate Request");
        try {
            EtsiTs103097Certificate aaCert = rootCA.rekeyAuthorizationCA(request);
            return aaCert.getEncoded();
        } catch (Exception e) {
            log.error("AA Rekey Certificate Request Failed!");
            log.error(e.getMessage());
            return e.getMessage().getBytes(StandardCharsets.UTF_8);
        }
    }

    @Override
    public byte[] rekeyEnrollmentCA(byte[] request) {
        log.log("Resolving EA Rekey Certificate Request");
        try {
            EtsiTs103097Certificate eaCert = rootCA.rekeyEnrollmentCA(request);
            return eaCert.getEncoded();
        } catch (Exception e) {
            log.error("EA Rekey Certificate Request Failed!");
            log.error(e.getMessage());
            return e.getMessage().getBytes(StandardCharsets.UTF_8);
        }
    }

    @Override
    public String revokeCertificate(String hash) {
        log.log("Revoking Certificate");
        try {
            boolean done = rootCA.revokeCertificate(hash);
            if (done)
                return "OK";
            else
                return "FAILED";

        } catch (Exception e) {
            log.error("Certificate Revocation Failed!");
            log.error(e.getMessage());
            return e.getMessage();
        }
    }
}
