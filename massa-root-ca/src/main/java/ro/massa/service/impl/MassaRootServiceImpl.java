package ro.massa.service.impl;


import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.camanagement.CaCertificateRequest;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.VerifyResult;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.springframework.stereotype.Component;
import ro.massa.common.MassaLog;
import ro.massa.common.MassaLogFactory;
import ro.massa.db.IRequestDao;
import ro.massa.db.impl.RequestDaoImpl;
import ro.massa.db.types.EntityType;
import ro.massa.db.types.RequestType;
import ro.massa.exception.MassaException;
import ro.massa.its.*;
import ro.massa.service.MassaRootService;

import java.nio.charset.StandardCharsets;

@Component
public class MassaRootServiceImpl implements MassaRootService {
    RootCA rootCA;
    MassaLog log = MassaLogFactory.getLog(MassaRootServiceImpl.class);

    public MassaRootServiceImpl() {
        log.log("Initializing MASSA Root Service");
        try {
            rootCA = AuthorityFactory.getInstance().createRootCa();
        } catch (Exception e) {
            log.error(e.getMessage());
        }
    }

    @Override
    public byte[] getSelfSignedCertificate() {
        log.log("Getting the Self Signed certificate of the Root CA");
        try {
            CaCredentials rootCredentials = rootCA.getSelfSignedCertificate();
            AuthorityFactory.getInstance().updateRootCa(rootCredentials);
            return rootCredentials.getCertificate().getEncoded();
        } catch (Exception e) {
            log.error(e.getMessage());
            return e.getMessage().getBytes(StandardCharsets.UTF_8);
        }
    }


    private byte[] certifyCA(byte[] request, DecodingAction decodingAction, CertificationAction certificationAction, IRequestDao caRequestDao) {
        try {
            VerifyResult<CaCertificateRequest> certRequest = decodingAction.operate(request);
            int id = caRequestDao.insert(certRequest);

            EtsiTs103097Certificate caCert = certificationAction.operate(certRequest);
            caRequestDao.updateCert(id, caCert);
            return caCert.getEncoded();

        } catch (MassaException me) {
            log.error(me.getMessage());
            return me.getMessage().getBytes(StandardCharsets.UTF_8);
        } catch (Exception e) {
            log.error("Certificate Request Failed!");
            log.error(e.getMessage());
            return e.getMessage().getBytes(StandardCharsets.UTF_8);
        }
    }

    @Override
    public byte[] certifyEnrollmentCA(byte[] request) {
        log.log("Resolving EA Certificate Request");
        IRequestDao caRequestDao = new RequestDaoImpl(RequestType.initial, EntityType.ea);
        return certifyCA(
                request,
                (req) -> {
                    return rootCA.decodeRequestMessage(req);
                },
                (req) -> {
                    return rootCA.initEnrollmentCA(req);
                },
                caRequestDao
        );
    }

    @Override
    public byte[] certifyAuthorizationCA(byte[] request) {
        log.log("Resolving AA Certificate Request");
        IRequestDao caRequestDao = new RequestDaoImpl(RequestType.initial, EntityType.aa);
        return certifyCA(
                request,
                (req) -> {
                    return rootCA.decodeRequestMessage(req);
                },
                (req) -> {
                    return rootCA.initAuthorizationCA(req);
                },
                caRequestDao
        );
    }

    @Override
    public byte[] rekeyAuthorizationCA(byte[] request) {
        log.log("Resolving AA Rekey Certificate Request");
        IRequestDao caRequestDao = new RequestDaoImpl(RequestType.rekey, EntityType.aa);
        return certifyCA(
                request,
                (req) -> {
                    return rootCA.decodeRekeyRequestMessage(req, EntityType.aa);
                },
                (req) -> {
                    return rootCA.initAuthorizationCA(req);
                },
                caRequestDao
        );
    }

    @Override
    public byte[] rekeyEnrollmentCA(byte[] request) {
        log.log("Resolving EA Rekey Certificate Request");
        IRequestDao caRequestDao = new RequestDaoImpl(RequestType.rekey, EntityType.ea);
        return certifyCA(
                request,
                (req) -> {
                    return rootCA.decodeRekeyRequestMessage(req, EntityType.ea);
                },
                (req) -> {
                    return rootCA.initAuthorizationCA(req);
                },
                caRequestDao
        );
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
