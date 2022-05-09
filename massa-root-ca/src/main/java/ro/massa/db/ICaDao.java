package ro.massa.db;

import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.camanagement.CaCertificateRequest;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.VerifyResult;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import ro.massa.exception.MassaException;

public interface ICaDao {
    int loadCa(int id) throws MassaException;
    EtsiTs103097Certificate getCertificate();
    String getKeyLabels();
    void updateCert(int id, EtsiTs103097Certificate certificate, String keyname) throws Exception;
}
