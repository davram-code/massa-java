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
    final static int SWEDEN = 752;

    static MassaLog log = MassaLogFactory.getLog(AuthorityFactory.class);
    private static AuthorityFactory single_instance = null;
    ICaDao caDao = new CaDaoImpl();
    IBinaryClient ctlClient;

    private AuthorityFactory() {
        Security.addProvider(new BouncyCastleProvider());
        ctlClient = new CtlClient();
    }

    public static AuthorityFactory getInstance() throws Exception {
        if (single_instance == null)
            single_instance = new AuthorityFactory();

        return single_instance;
    }

    public EnrollmentAuthority createEA() throws MassaException {
        try {

            byte[] ctlBytes = ctlClient.sendMessage("GET", "/getctl", null, null);
            CtlManager ctlManager = new CtlManager(ctlBytes);

            caDao.loadCa(7);
            EtsiTs103097Certificate EaCert = caDao.getCertificate();
            KeyPair signKeyPair = caDao.getSignKeyPair();
            KeyPair encKeyPair = caDao.getEncKeyPair();
//            String privateKeyPath = privateKeyLabels.split(" ")[0];
//            PrivateKey rootCASignPrvKey = Utils.readPrivateKey(privateKeyPath);
//
//            List<Integer> countries = new ArrayList<Integer>();
//            countries.add(SWEDEN);

            EtsiTs103097Certificate RootCaCert = Utils.readCertFromFile(MassaProperties.getInstance().getPathRootCaCert());
//            EtsiTs103097Certificate EaCert = Utils.readCertFromFile(MassaProperties.getInstance().getPathSelfCert());
//            PrivateKey signPrivateKey = Utils.readPrivateKey(MassaProperties.getInstance().getPathSignPrivateKey());
//            PublicKey signPublicKey = Utils.readPublicKey(MassaProperties.getInstance().getPathSignPublicKey());
//            PrivateKey encPrivateKey = Utils.readPrivateKey(MassaProperties.getInstance().getPathEncPrivateKey());
//            PublicKey encPublicKey = Utils.readPublicKey(MassaProperties.getInstance().getPathEncPublicKey());
            if (RootCaCert != null && signKeyPair != null && encKeyPair != null) {
                if (EaCert != null) { // CA has an active certificate
                    log.log(EaCert.toString());
                    return new EnrollmentAuthority(
                            RootCaCert,
                            EaCert,
                            signKeyPair,
                            encKeyPair,
                            ctlManager
                    );
                } else //CA doesn't have an active certificate
                {
                    return new EnrollmentAuthority(
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

//    public RootCA updateRootCa(CaCredentials caCredentials) throws MassaException {
//        try {
//            String signPrvKeyLabel = MassaProperties.getInstance().getPathSignPrivateKey();
//            String encPrvKeyLabel = MassaProperties.getInstance().getPathEncPrivateKey();
//
//            caDao.updateCert(20, caCredentials.getCertificate(), signPrvKeyLabel + " " + encPrvKeyLabel);
//
//            Utils.dump(signPrvKeyLabel, caCredentials.signKeys.getPrivate());
//            Utils.dump(encPrvKeyLabel, caCredentials.encKeys.getPrivate());
//
//            return createRootCa();
//        } catch (Exception e) {
//            throw new MassaException("Exception when creating RootCA: " + e.getMessage());
//        }
//    }
}
