package ro.massa.db.impl;

import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorization.InnerAtRequest;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.RequestVerifyResult;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.json.JSONObject;
import ro.massa.db.IAuthorizationRequestDao;
import ro.massa.db.types.RequestStatus;
import ro.massa.exception.MassaException;

import java.util.Date;

public class AuthorizationRequestDaoImpl extends MassaDaoImpl implements IAuthorizationRequestDao {


    public int insert(RequestVerifyResult<InnerAtRequest> ar) throws MassaException {
        JSONObject jsonPayload = new JSONObject()
                .put("request_date", ar.getHeaderInfo().getGenerationTime().toString())
                .put("request_status", RequestStatus.unprocessed)
                .put("ea_id", base64(ar.getValue().getSharedAtRequest().getEaId()))
                .put("key_tag", base64(ar.getValue().getSharedAtRequest().getKeyTag()))
                .put("certificate_format", base64(ar.getValue().getSharedAtRequest().getCertificateFormat()))
                .put("requested_subject_attribute", base64(ar.getValue().getSharedAtRequest().getRequestedSubjectAttributes()))
                .put("eov", "X")
                .put("received_date", new Date().toString())
                .put("processed_date", "X")
                .put("verification_pubkey", base64(ar.getValue().getPublicKeys().getVerificationKey().getValue()))
                .put("encryption_pubkey", base64(ar.getValue().getPublicKeys().getEncryptionKey().getPublicKey().getValue()))
                .put("app_permissions", base64(ar.getValue().getSharedAtRequest().getRequestedSubjectAttributes().getAppPermissions()))
                .put("cert_issue_permissions", base64(ar.getValue().getSharedAtRequest().getRequestedSubjectAttributes().getCertIssuePermissions()))
                .put("cert_request_permissions", "TODO")
//                    .put("certificate", "TODO")
                .put("aa_id", "TODO");

        JSONObject response = databaseClient.sendDatabaseMessage("POST", "/aa/authorization_requests", jsonPayload);

        testSuccess(response);

        return response.getInt("id");
    }

    @Override
    public int insertMalformed(byte[] ar) throws MassaException {
        JSONObject jsonPayload = new JSONObject()
                .put("request_status", RequestStatus.malformed)
                .put("request", base64(ar)); //TODO: ce facem cu request-urile malformed?

        JSONObject response = databaseClient.sendDatabaseMessage("POST", "/aa/authorization_requests", jsonPayload);

        testSuccess(response);

        return response.getInt("id");
    }

    @Override
    public void updateCert(int id, EtsiTs103097Certificate at) {
        JSONObject jsonPayload = new JSONObject()
                .put("id", id)
                .put("certificate", base64(at))
                .put("request_status", RequestStatus.certified);;

        databaseClient.sendDatabaseMessage("PUT", "/aa/authorization_requests", jsonPayload);
    }

    @Override
    public void updateStatus(int id, RequestStatus status) {
        JSONObject jsonPayload = new JSONObject()
                .put("id", id)
                .put("request_status", status);

        databaseClient.sendDatabaseMessage("PUT", "/aa/authorization_requests", jsonPayload);
    }

    public RequestVerifyResult<InnerAtRequest> select(int id) {
        return null;
    }

    public void delete(int id) {

    }
}
