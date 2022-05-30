package ro.massa.db;

import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import ro.massa.exception.MassaException;

import java.security.KeyPair;

public interface ICaDao {
    int loadCa(int id) throws MassaException;
    EtsiTs103097Certificate getCertificate();
    void updateCert() throws Exception;
    KeyPair getEncKeyPair();
    KeyPair getSignKeyPair();
}
