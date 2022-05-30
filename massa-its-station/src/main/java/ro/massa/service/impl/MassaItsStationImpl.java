package ro.massa.service.impl;


import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.EtsiTs103097DataEncryptedUnicast;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.springframework.stereotype.Component;
import ro.massa.common.MassaLog;
import ro.massa.common.MassaLogFactory;
import ro.massa.its.ITSClient;
import ro.massa.its.ITSStation;
import ro.massa.service.MassaItsStation;

import java.io.File;
import java.nio.file.Files;

@Component
public class MassaItsStationImpl implements MassaItsStation {
    MassaLog log = MassaLogFactory.getLog(MassaItsStationImpl.class);

    @Override
    public String test1() {
        try{
            log.log("Starting TEST 1");
            ITSStation itsStation = new ITSStation(
                    "certificates/EAcert.bin",
                    "certificates/AAcert.bin",
                    "certificates/rootCAcert.bin"
            );

            ITSClient itsClient = new ITSClient();
            EtsiTs103097DataEncryptedUnicast ecRequest = itsStation.generateInitialEnrollmentRequest();
            byte [] ecResponse = itsClient.sendEcRequest(ecRequest.getEncoded());
            EtsiTs103097Certificate ecCert = itsStation.verifyEnrolmentResponse(ecResponse);
            log.log("Enrollment Credential:");
            log.log(ecCert.toString());

            EtsiTs103097DataEncryptedUnicast atRequest = itsStation.generateAuthorizationRequestMessage(ecCert);
            byte [] atResponse = itsClient.sendAtRequest(atRequest.getEncoded());
            EtsiTs103097Certificate atCert = itsStation.verifyAuthorizationResponse(atResponse);
            log.log("Authorization Ticket:");
            log.log(atCert.toString());

            return "\nTEST 1 PASSED";
        }
        catch (Exception e)
        {
            return  "\nTEST 1 FAILED: " + e.getMessage();
        }
    }
}
