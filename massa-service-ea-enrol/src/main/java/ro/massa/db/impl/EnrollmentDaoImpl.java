package ro.massa.db.impl;

import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.enrollment.InnerEcRequest;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.RequestVerifyResult;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.json.JSONObject;
import ro.massa.db.DatabaseClient;
import ro.massa.db.IEnrollmentDao;
import ro.massa.db.types.RequestStatus;
import ro.massa.db.types.RequestType;

import java.util.Date;

public class EnrollmentDaoImpl extends MassaDaoImpl implements IEnrollmentDao {
    @Override
    public String insert(RequestVerifyResult<InnerEcRequest> enrollmentRequest) {
        JSONObject jsonPayload = new JSONObject()
                .put("requestdate", enrollmentRequest.getHeaderInfo().getGenerationTime().toString())
                .put("request_type", new RequestType(enrollmentRequest).getValue())
                .put("requeststatus_id", RequestStatus.unprocessed)
                .put("certificateid", base64(enrollmentRequest.getSignerIdentifier().getValue()))
//                "eov": "date",
                .put("receiveddate", new Date().toString())
//                "processeddate": "date",
                .put("verificationpubkey", base64(enrollmentRequest.getValue().getPublicKeys().getVerificationKey().getValue()))
                .put("encryptionpubkey", base64(enrollmentRequest.getValue().getPublicKeys().getEncryptionKey().getPublicKey().getValue()));
//                .put("apppermissions", base64(enrollmentRequest.getValue().getSharedAtRequest().getRequestedSubjectAttributes().getAppPermissions()))
//                .put("certissuepermissions", base64(enrollmentRequest.getValue().getSharedAtRequest().getRequestedSubjectAttributes().getCertIssuePermissions()))
//                "certrequestpermissions": "base64 value",
//                "certificate": null/"base64 value",
//                "ea_id": id from EA table

        try {
            DatabaseClient.sendDatabaseMessage("POST", "/ea/enrolment", jsonPayload);
        } catch (Exception e) {
            log.log("Not implemented: " + e.getMessage());
        }


        return "UniqueID";
    }

    @Override
    public String insertMalformed(byte[] enrollmentRequest) {
        JSONObject jsonPayload = new JSONObject()
                .put("requeststatus_id", RequestStatus.malformed)
                .put("request", base64(enrollmentRequest)); //TODO: ce facem cu request-urile malformed?
        try {
            DatabaseClient.sendDatabaseMessage("POST", "/ea/enrolment", jsonPayload);
        } catch (Exception e) {
            log.log("Not implemented: " + e.getMessage());
        }

        return "UniqueID";
    }

    @Override
    public void updateCert(String id, EtsiTs103097Certificate ec) {
        JSONObject jsonPayload = new JSONObject()
                .put("id", id)
                .put("certificate", base64(ec))
                .put("processeddate", new Date().toString())
                .put("requeststatus_id", RequestStatus.certified);
        ;
        try {
            DatabaseClient.sendDatabaseMessage("PUT", "/ea/enrollment", jsonPayload);
        } catch (Exception e) {
            log.log("Not implemented: " + e.getMessage());
        }

    }

    @Override
    public void updateStatus(String id, RequestStatus status) {
        JSONObject jsonPayload = new JSONObject()
                .put("id", id)
                .put("requeststatus_id", status);
        try {
            DatabaseClient.sendDatabaseMessage("PUT", "/ea/enrolment", jsonPayload);
        } catch (Exception e) {
            log.log("Not implemented: " + e.getMessage());
        }
    }
}
