package massa.its.init;

import massa.Utils;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature;

import java.security.KeyPair;

public class StationInitializer extends Initializer {
    private KeyPair enrolCredSignKeys;
    private KeyPair enrolCredEncKeys;

    private KeyPair authTicketSignKeys; // TO SAVE
    private KeyPair authTicketEncKeys; // TO SAVE

    public StationInitializer(String pathInitDirectory) throws Exception{
        super(pathInitDirectory);
    }

    public void init() throws Exception
    {
        enrolCredSignKeys = cryptoManager.generateKeyPair(Signature.SignatureChoices.ecdsaNistP256Signature);
        enrolCredEncKeys = cryptoManager.generateKeyPair(Signature.SignatureChoices.ecdsaNistP256Signature);
        authTicketSignKeys = cryptoManager.generateKeyPair(Signature.SignatureChoices.ecdsaNistP256Signature);
        authTicketEncKeys = cryptoManager.generateKeyPair(Signature.SignatureChoices.ecdsaNistP256Signature);

        Utils.dumpToFile(pathInitDirectory + "/CredSignKey.pub", enrolCredSignKeys.getPublic());
        Utils.dumpToFile(pathInitDirectory + "/CredSignKey.prv", enrolCredSignKeys.getPrivate());
        Utils.dumpToFile(pathInitDirectory + "/CredEncKey.pub", enrolCredEncKeys.getPublic());
        Utils.dumpToFile(pathInitDirectory + "/CredEncKey.prv", enrolCredEncKeys.getPrivate());
        Utils.dumpToFile(pathInitDirectory + "/TicketSignKey.pub", authTicketSignKeys.getPublic());
        Utils.dumpToFile(pathInitDirectory + "/TicketSignKey.prv", authTicketSignKeys.getPrivate());
        Utils.dumpToFile(pathInitDirectory + "/TicketEncKey.pub", authTicketEncKeys.getPublic());
        Utils.dumpToFile(pathInitDirectory + "/TicketEncKey.prv", authTicketEncKeys.getPrivate());
    }
}
