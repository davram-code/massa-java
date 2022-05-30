package ro.massa.db.impl;

import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.enrollment.InnerEcRequest;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.RequestVerifyResult;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.json.JSONObject;
import ro.massa.db.DatabaseClient;
import ro.massa.db.IEnrollmentDao;
import ro.massa.db.types.RequestStatus;
import ro.massa.db.types.RequestType;
import ro.massa.exception.MassaException;
import ro.massa.its.ITSEntity;

import java.util.Date;

public class EnrollmentDaoImpl extends MassaDaoImpl implements IEnrollmentDao {
    @Override
    public int insert(RequestVerifyResult<InnerEcRequest> enrollmentRequest) throws MassaException {
        JSONObject jsonPayload = new JSONObject()
                .put("request_date", enrollmentRequest.getHeaderInfo().getGenerationTime().asDate().toString())
                .put("request_type_id", new RequestType(enrollmentRequest).getValue())
                .put("request_status_id", RequestStatus.unprocessed.getValue())
                .put("certificate_id", "null")
//                "eov": "date",
                .put("received_date", new Date().toString())
//                "processeddate": "date",
                .put("verification_pubkey", base64(enrollmentRequest.getValue().getPublicKeys().getVerificationKey().getValue()))
                .put("encryption_pubkey", base64(enrollmentRequest.getValue().getPublicKeys().getEncryptionKey().getPublicKey().getValue()));
//                .put("apppermissions", base64(enrollmentRequest.getValue().getSharedAtRequest().getRequestedSubjectAttributes().getAppPermissions()))
//                .put("certissuepermissions", base64(enrollmentRequest.getValue().getSharedAtRequest().getRequestedSubjectAttributes().getCertIssuePermissions()))
//                "certrequestpermissions": "base64 value",
//                "certificate": null/"base64 value",
//                "ea_id": id from EA table


        JSONObject response = DatabaseClient.sendDatabaseMessage("POST", "/ea/enrolment", jsonPayload);

        testSuccess(response);

        return response.getInt("id");
    }

    @Override
    public void insertMalformed(byte[] enrollmentRequest){
//        try {
//            JSONObject jsonPayload = new JSONObject()
//                    .put("request_status_id", RequestStatus.malformed.getValue());
//                    //.put("request", base64(enrollmentRequest)); //TODO: ce facem cu request-urile malformed?
//            JSONObject response = DatabaseClient.sendDatabaseMessage("POST", "/ea/enrolment", jsonPayload);
//            testSuccess(response);
//
//        } catch (Exception e) {
//            log.log("Unable to insert malformed request in DB: " + e.getMessage());
//        }
    }

    @Override
    public void updateCert(int id, EtsiTs103097Certificate certificate) throws MassaException {
        try {
            Date eov = addYearsToDate(certificate.getToBeSigned().getValidityPeriod().getStart().asDate(),
                    certificate.getToBeSigned().getValidityPeriod().getDuration().getValueAsInt());

            JSONObject jsonPayload = new JSONObject()
                    .put("id", id)
                    .put("certificate", base64(certificate))
                    .put("certificate_id", ITSEntity.computeHashedId8String(certificate))
                    .put("eov", eov.toString())
                    .put("processed_date", new Date().toString())
                    .put("request_status_id", RequestStatus.certified.getValue());


            JSONObject response = DatabaseClient.sendDatabaseMessage("PUT", "/ea/enrolment", jsonPayload);
            testSuccess(response);

        } catch (Exception e) {
            throw new MassaException("DB exception: updateCert :", e);
        }

    }

    @Override
    public void updateStatus(int id, RequestStatus status) throws MassaException {
        try {
            JSONObject jsonPayload = new JSONObject()
                    .put("id", id)
                    .put("request_status_id", status.getValue());

            JSONObject response = DatabaseClient.sendDatabaseMessage("PUT", "/ea/enrolment", jsonPayload);
            testSuccess(response);

        } catch (Exception e) {
            throw new MassaException("DB exception: updateStatus :", e);
        }
    }
}
