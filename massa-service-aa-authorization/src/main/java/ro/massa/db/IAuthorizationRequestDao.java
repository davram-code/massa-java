package ro.massa.db;


import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorization.InnerAtRequest;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.RequestVerifyResult;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;

public interface IAuthorizationRequestDao {
    String insert(RequestVerifyResult<InnerAtRequest> ar);
    void update(String id, EtsiTs103097Certificate at);
//    RequestVerifyResult<InnerAtRequest> select(int id);
    void delete(int id);
}
