package ro.massa.its;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.*;
import ro.massa.common.MassaLog;
import ro.massa.common.MassaLogFactory;
import ro.massa.common.Utils;
import ro.massa.db.ICaDao;
import ro.massa.db.impl.CaDaoImpl;
import ro.massa.exception.MassaException;
import ro.massa.properties.MassaProperties;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.*;

public class AuthorityFactory {
    final static int SWEDEN = 752;

    static MassaLog log = MassaLogFactory.getLog(AuthorityFactory.class);
    private static AuthorityFactory single_instance = null;
    ICaDao caDao = new CaDaoImpl();

    private AuthorityFactory()
    {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static AuthorityFactory getInstance() throws Exception
    {
        if (single_instance == null)
            single_instance = new AuthorityFactory();

        return single_instance;
    }

    public RootCA createRootCa() throws MassaException {
        try {
            caDao.loadCa(20);
            EtsiTs103097Certificate certificate = caDao.getCertificate();
            String privateKeyLabels = caDao.getKeyLabels();
            String privateKeyPath = privateKeyLabels.split(" ")[0];
            PrivateKey rootCASignPrvKey = Utils.readPrivateKey(privateKeyPath);

            List<Integer> countries = new ArrayList<Integer>();
            countries.add(SWEDEN);
            return new RootCA(certificate, rootCASignPrvKey);
        } catch (Exception e) {
            throw new MassaException("Exception when creating RootCA: " + e.getMessage());
        }
    }

    public RootCA updateRootCa(CaCredentials caCredentials) throws MassaException {
        try {
            String signPrvKeyLabel = MassaProperties.getInstance().getPathSignPrivateKey();
            String encPrvKeyLabel = MassaProperties.getInstance().getPathEncPrivateKey();

            caDao.updateCert(20, caCredentials.getCertificate(), signPrvKeyLabel + " " + encPrvKeyLabel);

            Utils.dump(signPrvKeyLabel, caCredentials.signKeys.getPrivate());
            Utils.dump(encPrvKeyLabel, caCredentials.encKeys.getPrivate());

            return createRootCa();
        } catch (Exception e) {
            throw new MassaException("Exception when creating RootCA: " + e.getMessage());
        }
    }
}
