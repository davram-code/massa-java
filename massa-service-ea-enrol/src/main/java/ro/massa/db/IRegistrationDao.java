package ro.massa.db;

import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.enrollment.InnerEcRequest;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.RequestVerifyResult;
import ro.massa.exception.MassaException;

public interface IRegistrationDao {
        //INSERT
        boolean checkRegistration(RequestVerifyResult<InnerEcRequest> enrollmentRequest) throws MassaException;
}
