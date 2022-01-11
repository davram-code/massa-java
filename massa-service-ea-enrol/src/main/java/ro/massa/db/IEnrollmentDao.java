package ro.massa.db;

import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import ro.massa.db.types.RequestStatus;

public interface IEnrollmentDao {
    //INSERT
    String insert();
    String insertMalformed(byte [] ar);

    //UPDATE
    void updateCert(String id, EtsiTs103097Certificate at);
    void updateStatus(String id, RequestStatus status);
}
