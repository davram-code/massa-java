package ro.massa.db;

import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.camanagement.CaCertificateRequest;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.VerifyResult;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import ro.massa.exception.MassaException;

import java.security.PublicKey;

public interface IRequestDao {
    int insert(VerifyResult<CaCertificateRequest> request) throws MassaException;
    void updateCert(int id, EtsiTs103097Certificate certificate) throws Exception;
}
