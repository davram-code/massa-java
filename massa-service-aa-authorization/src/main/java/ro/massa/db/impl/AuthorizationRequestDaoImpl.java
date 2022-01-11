package ro.massa.db.impl;

import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorization.InnerAtRequest;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.RequestVerifyResult;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.json.JSONObject;
import ro.massa.db.DatabaseClient;
import ro.massa.db.IAuthorizationRequestDao;
import ro.massa.db.types.RequestStatus;

import java.util.Date;

public class AuthorizationRequestDaoImpl extends MassaDaoImpl implements IAuthorizationRequestDao {


    public String insert(RequestVerifyResult<InnerAtRequest> ar) {
        JSONObject jsonPayload = new JSONObject()
                .put("requestdate", new Date().toString())
                .put("requeststatus_id", RequestStatus.unprocessed)
                .put("ea_id", base64(ar.getValue().getSharedAtRequest().getEaId()))
                .put("keytag", base64(ar.getValue().getSharedAtRequest().getKeyTag()))
                .put("certificateformat", base64(ar.getValue().getSharedAtRequest().getCertificateFormat()))
                .put("requestedsubjectattreibute", base64(ar.getValue().getSharedAtRequest().getRequestedSubjectAttributes()))
                .put("eov", "X")
                .put("receiveddate", "X")
                .put("processeddate", "X")
                .put("verificationpubkey", base64(ar.getValue().getPublicKeys().getVerificationKey().getValue()))
                .put("encryptionpubkey", base64(ar.getValue().getPublicKeys().getEncryptionKey().getPublicKey().getValue()))
                .put("apppermissions", base64(ar.getValue().getSharedAtRequest().getRequestedSubjectAttributes().getAppPermissions()))
                .put("certissuepermissions", base64(ar.getValue().getSharedAtRequest().getRequestedSubjectAttributes().getCertIssuePermissions()))
                .put("certrequestpermissions", "TODO")
//                    .put("certificate", "TODO")
                .put("aa_id", "TODO");

        DatabaseClient.sendDatabaseMessage("POST", "/aa/authorization_requests", jsonPayload);

        return "UniqueID";
    }

    @Override
    public String insertMalformed(byte[] ar) {
        JSONObject jsonPayload = new JSONObject()
                .put("requestdate", new Date().toString())
                .put("requeststatus_id", RequestStatus.malformed)
                .put("request", base64(ar)); //TODO: ce facem cu request-urile malformed?

        DatabaseClient.sendDatabaseMessage("POST", "/aa/authorization_requests", jsonPayload);

        return "UniqueID";
    }

    @Override
    public void updateCert(String id, EtsiTs103097Certificate at) {
        JSONObject jsonPayload = new JSONObject()
                .put("id", id)
                .put("certificate", base64(at))
                .put("requeststatus_id", RequestStatus.certified);;

        DatabaseClient.sendDatabaseMessage("PUT", "/aa/authorization_requests", jsonPayload);
    }

    @Override
    public void updateStatus(String id, RequestStatus status) {
        JSONObject jsonPayload = new JSONObject()
                .put("id", id)
                .put("requeststatus_id", status);

        DatabaseClient.sendDatabaseMessage("PUT", "/aa/authorization_requests", jsonPayload);
    }

    public RequestVerifyResult<InnerAtRequest> select(int id) {
        return null;
    }

    public void delete(int id) {

    }
}
