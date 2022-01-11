package ro.massa.db;

import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.enrollment.InnerEcRequest;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.RequestVerifyResult;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import ro.massa.db.types.RequestStatus;

public interface IEnrollmentDao {
    //INSERT
    String insert(RequestVerifyResult<InnerEcRequest> enrollmentRequest);
    String insertMalformed(byte [] ar);

    //UPDATE
    void updateCert(String id, EtsiTs103097Certificate at);
    void updateStatus(String id, RequestStatus status);
}
