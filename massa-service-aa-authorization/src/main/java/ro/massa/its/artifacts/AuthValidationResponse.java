package ro.massa.its.artifacts;

import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorizationvalidation.AuthorizationValidationResponse;

import javax.sound.midi.MidiDeviceReceiver;

public class AuthValidationResponse {


    private AuthorizationValidationResponse authorizationValidationResponse;
    private int idRequest;
    private int id;

    public AuthValidationResponse(AuthorizationValidationResponse authorizationValidationResponse, int idRequest, int id)
    {
        this.authorizationValidationResponse = authorizationValidationResponse;
        this.idRequest = idRequest;
        this.id = id;
    }


    public AuthorizationValidationResponse getValue() {
        return authorizationValidationResponse;
    }

    public int getIdRequest() {
        return idRequest;
    }

    public int getId() {
        return id;
    }

}
