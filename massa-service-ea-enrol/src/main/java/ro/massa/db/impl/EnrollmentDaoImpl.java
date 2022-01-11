package ro.massa.db.impl;

import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.enrollment.InnerEcRequest;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.RequestVerifyResult;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import ro.massa.db.IEnrollmentDao;
import ro.massa.db.types.RequestStatus;

public class EnrollmentDaoImpl implements IEnrollmentDao {
    @Override
    public String insert(RequestVerifyResult<InnerEcRequest> enrollmentRequest) {
        return null;
    }

    @Override
    public String insertMalformed(byte[] ar) {
        return null;
    }

    @Override
    public void updateCert(String id, EtsiTs103097Certificate at) {

    }

    @Override
    public void updateStatus(String id, RequestStatus status) {

    }
}
