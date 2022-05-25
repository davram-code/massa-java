package ro.massa.db;

import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import ro.massa.exception.MassaException;

public interface IEnrollmentDao {
    EtsiTs103097Certificate getEcCert(String signer) throws MassaException;
}
