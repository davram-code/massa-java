package ro.massa.common;

import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorization.InnerAtRequest;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorizationvalidation.AuthorizationValidationRequest;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorizationvalidation.AuthorizationValidationResponse;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.RequestVerifyResult;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.EncryptResult;
import ro.massa.its.artifacts.AuthRequest;
import ro.massa.its.artifacts.AuthValidationRequest;
import ro.massa.its.artifacts.AuthValidationResponse;
import ro.massa.service.impl.MassaAuthorizationServiceImpl;

public class MassaDB {
    static MassaLog log = MassaLogFactory.getLog(MassaAuthorizationServiceImpl.class);

    static int AtRequestIndex = 0;
    static public AuthRequest store(RequestVerifyResult<InnerAtRequest> authorizationRequest)
    {
        log.log("Authorization Request #" + AtRequestIndex+ "   " + authorizationRequest.toString());
        return new AuthRequest(authorizationRequest, AtRequestIndex++);
    }

    static int AtValRequestIndex = 0;
    static public AuthValidationRequest store(EncryptResult authorizationValidationRequest, AuthRequest authoriztionRequest)
    {
        log.log("Authorization Validation Request #" + AtValRequestIndex + "   " + authorizationValidationRequest.toString());
        return new AuthValidationRequest(authorizationValidationRequest, authoriztionRequest.getId(), AtValRequestIndex++);
    }

    static int AtValResponseIndex = 0;
    static public AuthValidationResponse store(AuthorizationValidationResponse authorizationValidationResponse, AuthValidationRequest authValidationRequest)
    {
        log.log("Authorization Validation Response #" + AtValResponseIndex + "   " + authorizationValidationResponse.toString());
        return new AuthValidationResponse(authorizationValidationResponse, authValidationRequest.getId(), AtValResponseIndex++);
    }

    static int AtIndex = 0;
    static public int store(EtsiTs103097Certificate authTicketCert, AuthRequest authRequest)
    {
        log.log("Authorization Ticket #" + AtIndex + " for Request #" + authRequest.getId() + "  " + authTicketCert.toString());
        return AtIndex++;
    }



}
