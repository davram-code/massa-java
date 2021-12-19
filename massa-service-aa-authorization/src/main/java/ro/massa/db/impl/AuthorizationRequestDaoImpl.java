package ro.massa.db.impl;

import org.certificateservices.custom.c2x.common.Encodable;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorization.InnerAtRequest;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.RequestVerifyResult;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.json.JSONObject;
import org.springframework.util.Base64Utils;
import ro.massa.common.MassaLog;
import ro.massa.common.MassaLogFactory;
import ro.massa.db.DatabaseClient;
import ro.massa.db.IAuthorizationRequestDao;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.util.Date;

public class AuthorizationRequestDaoImpl implements IAuthorizationRequestDao {
    static private MassaLog log = MassaLogFactory.getLog(AuthorizationRequestDaoImpl.class);
    private byte[] getBytes(Encodable encodable)
    {
        try{
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(baos);
            encodable.encode(dos);
            byte[] data = baos.toByteArray();
            return data;
        }
        catch (Exception e)
        {
            log.log(e.toString());
            return new byte[]{};
        }
    }
    private String base64(Encodable encodable)
    {
        return base64(getBytes(encodable));
    }

    private String base64(byte [] data)
    {
        if(data.length > 0)
            return new String(Base64Utils.encode(data));
        else
            return "null"; //TODO
    }

    public String insert(RequestVerifyResult<InnerAtRequest> ar)  {
            JSONObject jsonPayload = new JSONObject()
                    .put("requestdate", new Date().toString())
                    .put("requeststatus_id", "TODO")
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

    public void update(String id, EtsiTs103097Certificate at) {
        JSONObject jsonPayload = new JSONObject()
                .put("id", id)
                .put("certificate", base64(at));

        DatabaseClient.sendDatabaseMessage("PUT", "/aa/authorization_requests", jsonPayload);
    }

    public RequestVerifyResult<InnerAtRequest> select(int id) {
        return null;
    }

    public void delete(int id) {

    }
}
