package ro.massa.its.artifacts;

import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorization.InnerAtRequest;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.RequestVerifyResult;

public class AuthRequest {
    private RequestVerifyResult<InnerAtRequest> authorizationRequest;
    private int id;

    public AuthRequest(RequestVerifyResult<InnerAtRequest>authorizationRequest, int id)
    {
        this.authorizationRequest = authorizationRequest;
        this.id = id;
    }

    public RequestVerifyResult<InnerAtRequest> getValue()
    {
        return authorizationRequest;
    }

    public int getId()
    {
        return id;
    }

}
