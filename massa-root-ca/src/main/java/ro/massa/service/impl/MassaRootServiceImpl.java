package ro.massa.service.impl;


import org.certificateservices.custom.c2x.common.Encodable;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.camanagement.CaCertificateRequest;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.VerifyResult;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.springframework.stereotype.Component;
import ro.massa.common.MassaLog;
import ro.massa.common.MassaLogFactory;
import ro.massa.common.Utils;
import ro.massa.db.DatabaseClient;
import ro.massa.db.ICaRequestDao;
import ro.massa.db.impl.CaRequestDaoImpl;
import ro.massa.db.types.EntityType;
import ro.massa.db.types.RequestType;
import ro.massa.exception.MassaException;
import ro.massa.its.CertificationAction;
import ro.massa.its.DecodingAction;
import ro.massa.its.RootCA;
import ro.massa.service.MassaRootService;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;

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


    private byte[] certifyCA(byte[] request, DecodingAction decodingAction, CertificationAction certificationAction, ICaRequestDao caRequestDao) {
        try {
            VerifyResult<CaCertificateRequest> certRequest = decodingAction.operate(request);
            int id = caRequestDao.insert(certRequest);

            EtsiTs103097Certificate eaCert = certificationAction.operate(certRequest);
            caRequestDao.updateCert(id, eaCert);
            return eaCert.getEncoded();

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
        ICaRequestDao caRequestDao = new CaRequestDaoImpl(RequestType.initial, EntityType.ea);
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
        ICaRequestDao caRequestDao = new CaRequestDaoImpl(RequestType.initial, EntityType.aa);
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
        ICaRequestDao caRequestDao = new CaRequestDaoImpl(RequestType.rekey, EntityType.aa);
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
        ICaRequestDao caRequestDao = new CaRequestDaoImpl(RequestType.rekey, EntityType.ea);
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
