package ro.massa.db;


import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorization.InnerAtRequest;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.RequestVerifyResult;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import ro.massa.db.types.RequestStatus;
import ro.massa.exception.MassaException;

public interface IAuthorizationRequestDao {

    //INSERT
    int insert(RequestVerifyResult<InnerAtRequest> ar) throws MassaException;
    int insertMalformed(byte [] ar) throws MassaException;

    // UPDATE
    void updateCert(int id, EtsiTs103097Certificate at);
    void updateStatus(int id, RequestStatus status);

    //SELECT
    //    RequestVerifyResult<InnerAtRequest> select(int id);

    // DELETE
    void delete(int id);
}
