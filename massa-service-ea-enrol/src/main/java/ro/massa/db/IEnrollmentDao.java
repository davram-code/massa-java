package ro.massa.db;

import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.enrollment.InnerEcRequest;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.RequestVerifyResult;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import ro.massa.db.types.RequestStatus;
import ro.massa.exception.MassaException;

public interface IEnrollmentDao {
    //INSERT
    int insert(RequestVerifyResult<InnerEcRequest> enrollmentRequest) throws MassaException;
    void insertMalformed(byte [] ar);

    //UPDATE
    void updateCert(int id, EtsiTs103097Certificate at)  throws MassaException ;
    void updateStatus(int id, RequestStatus status) throws MassaException;
}
