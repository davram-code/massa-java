package ro.massa.db;

import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorization.InnerAtRequest;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.RequestVerifyResult;
import ro.massa.its.AuthorizationAuthority;

public interface IAuthorizationAuthorityDao {
    String insert(AuthorizationAuthority ar);
}
