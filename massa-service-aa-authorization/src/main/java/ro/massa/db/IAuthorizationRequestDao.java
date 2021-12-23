package ro.massa.db;


import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorization.InnerAtRequest;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.RequestVerifyResult;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import ro.massa.db.types.RequestStatus;

public interface IAuthorizationRequestDao {

    //INSERT
    String insert(RequestVerifyResult<InnerAtRequest> ar);
    String insertMalformed(byte [] ar);

    // UPDATE
    void updateCert(String id, EtsiTs103097Certificate at);
    void updateStatus(String id, RequestStatus status);

    //SELECT
    //    RequestVerifyResult<InnerAtRequest> select(int id);

    // DELETE
    void delete(int id);
}
