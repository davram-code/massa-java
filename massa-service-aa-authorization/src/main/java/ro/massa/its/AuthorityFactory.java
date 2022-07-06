package ro.massa.its;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import ro.massa.common.MassaLog;
import ro.massa.common.MassaLogFactory;
import ro.massa.common.Utils;
import ro.massa.db.ICaDao;
import ro.massa.db.impl.CaDaoImpl;
import ro.massa.exception.MassaException;
import ro.massa.properties.MassaProperties;
import ro.massa.rest.CtlClient;
import ro.massa.rest.IBinaryClient;

import java.security.KeyPair;
import java.security.Security;

public class AuthorityFactory {
    static MassaLog log = MassaLogFactory.getLog(AuthorityFactory.class);
    private static AuthorityFactory single_instance = null;
    ICaDao caDao = new CaDaoImpl();
    CtlClient ctlClient;

    private AuthorityFactory() {
        Security.addProvider(new BouncyCastleProvider());
        ctlClient = new CtlClient();
    }

    public static AuthorityFactory getInstance() throws Exception {
        if (single_instance == null)
            single_instance = new AuthorityFactory();

        return single_instance;
    }

//    public ValidationEnrollmentAuthority createEA() throws MassaException {
//        try {
//            byte[] ctlBytes = ctlClient.sendMessage(
//                    "GET",
//                    "/getctl",
//                    null,
//                    null
//            );
//
//            //CtlManager ctlManager = new CtlManager(ctlBytes);
//
//
//            caDao.loadCa(7);
//            EtsiTs103097Certificate EaCert = caDao.getCertificate();
//            KeyPair signKeyPair = caDao.getSignKeyPair();
//            KeyPair encKeyPair = caDao.getEncKeyPair();
//            EtsiTs103097Certificate RootCaCert = Utils.readCertFromFile(MassaProperties.getInstance().getPathRootCaCert());
//
//            if (RootCaCert != null && signKeyPair != null && encKeyPair != null) {
//                if (EaCert != null) { // CA has an active certificate
//                    log.log(EaCert.toString());
//                    return new ValidationEnrollmentAuthority(
//                            RootCaCert,
//                            EaCert,
//                            signKeyPair,
//                            encKeyPair,
//                            ctlBytes
//                    );
//                } else //CA doesn't have an active certificate
//                {
//                    return new ValidationEnrollmentAuthority(
//                            RootCaCert,
//                            signKeyPair,
//                            encKeyPair
//                    );
//                }
//            }
//        } catch (Exception e) {
//            throw new MassaException("Exception when creating Enrollment EA: " + e.getMessage());
//        }
//        throw new MassaException("Could not load Enrollment EA");
//    }

    public AuthorizationAuthority createAA() throws MassaException{
        try {
            byte[] ctlBytes = ctlClient.getCtlFromDc();

            //CtlManager ctlManager = new CtlManager(ctlBytes);


            caDao.loadCa(5);
            EtsiTs103097Certificate EaCert = caDao.getCertificate();
            KeyPair signKeyPair = caDao.getSignKeyPair();
            KeyPair encKeyPair = caDao.getEncKeyPair();
            EtsiTs103097Certificate RootCaCert = Utils.readCertFromFile(MassaProperties.getInstance().getPathRootCaCert());

            if (RootCaCert != null && signKeyPair != null && encKeyPair != null) {
                if (EaCert != null) { // CA has an active certificate
                    log.log(EaCert.toString());
                    return new AuthorizationAuthority(
                            RootCaCert,
                            EaCert,
                            signKeyPair,
                            encKeyPair,
                            ctlBytes
                    );
                } else //CA doesn't have an active certificate
                {
                    return new AuthorizationAuthority(
                            RootCaCert,
                            signKeyPair,
                            encKeyPair
                    );
                }
            }
        } catch (Exception e) {
            throw new MassaException("Exception when creating Enrollment EA: " + e.getMessage());
        }
        throw new MassaException("Could not load Enrollment EA");
    }
}
