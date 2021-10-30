package ro.massa.its.artifacts;

import org.certificateservices.custom.c2x.ieee1609dot2.generator.EncryptResult;

public class AuthValidationRequest {
    EncryptResult authorizationValidation;
    int idRequest;
    int id;

    public AuthValidationRequest(EncryptResult authorizationValidation, int idRequest, int id)
    {
        this.authorizationValidation = authorizationValidation;
        this.idRequest = idRequest;
        this.id = id;
    }

    public EncryptResult getValue(){
        return this.authorizationValidation;
    }

    public int getId(){
        return this.id;
    }

    public int getIdRequest(){
        return this.idRequest;
    }
}
