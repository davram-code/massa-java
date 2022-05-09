package ro.massa.db.impl;

import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.camanagement.CaCertificateRequest;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.VerifyResult;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.json.JSONObject;
import ro.massa.db.DatabaseClient;
import ro.massa.db.IRequestDao;
import ro.massa.db.UrlQuerry;
import ro.massa.db.types.EntityType;
import ro.massa.db.types.RequestStatus;
import ro.massa.db.types.RequestType;
import ro.massa.exception.MassaException;

import java.io.IOException;
import java.util.Date;

public class RequestDaoImpl extends MassaDaoImpl implements IRequestDao {

    private  RequestType requestType;
    private EntityType entityType;
    private VerifyResult<CaCertificateRequest> request;
    private String receivedate = null;
    public RequestDaoImpl(RequestType requestType, EntityType entityType)
    {
        this.requestType = requestType;
        this.entityType = entityType;
    }


    @Override
    public int insert(VerifyResult<CaCertificateRequest> request) throws MassaException {

        log.log(request.getHeaderInfo().toString());
        this.request = request;
        this.receivedate = new Date().toString();

        JSONObject jsonPayload = new JSONObject()
                .put("requestdate", request.getHeaderInfo().getGenerationTime().asDate().toString())
                .put("requesttype_id", requestType.getValue())
                .put("entitytype_id", entityType.getValue())
                .put("requeststatus_id", RequestStatus.unprocessed.getValue())
                .put("certificate", "null")
                .put("certificate_id", -1)
                .put("eov", "1970-01-01")
                .put("receiveddate", receivedate)
                .put("processeddate", "1970-01-01")
                .put("verificationpubkey", base64(request.getValue().getPublicKeys().getVerificationKey().getValue()))
                .put("encryptionpubkey", base64(request.getValue().getPublicKeys().getEncryptionKey().getPublicKey().getValue()))
                .put("apppermissions", base64(request.getValue().getRequestedSubjectAttributes().getAppPermissions()))
                .put("certissuepermissions", "null")
                .put("certrequestpermissions", "null")
                .put("caid", 20);

        JSONObject response = DatabaseClient.sendDatabaseMessage("POST", "/rootca/request", jsonPayload);

        testSuccess(response);

        return response.getInt("id");
    }

    @Override
    public void updateCert(int id, EtsiTs103097Certificate certificate) throws MassaException {

        try {
            Date eov = addYearsToDate(certificate.getToBeSigned().getValidityPeriod().getStart().asDate(),
                    certificate.getToBeSigned().getValidityPeriod().getDuration().getValueAsInt());

            JSONObject jsonPayload = new JSONObject()
                    .put("id", id)
                    .put("requestdate", request.getHeaderInfo().getGenerationTime().asDate().toString())
                    .put("requesttype_id", requestType.getValue())
                    .put("entitytype_id", entityType.getValue())
                    .put("requeststatus_id", RequestStatus.certified.getValue())
                    .put("certificate", base64(certificate.getEncoded()))
                    .put("certificate_id", Integer.toString(certificate.hashCode()))
                    .put("eov", eov.toString())
                    .put("receiveddate", receivedate)
                    .put("processeddate", new Date().toString())
                    .put("verificationpubkey", base64(request.getValue().getPublicKeys().getVerificationKey().getValue()))
                    .put("encryptionpubkey", base64(request.getValue().getPublicKeys().getEncryptionKey().getPublicKey().getValue()))
                    .put("apppermissions", base64(request.getValue().getRequestedSubjectAttributes().getAppPermissions()))
                    .put("certissuepermissions", "null")
                    .put("certrequestpermissions", "null")
                    .put("caid", 20);

            JSONObject response = DatabaseClient.sendDatabaseMessage("PUT", "/rootca/request", jsonPayload, new UrlQuerry().add("id", Integer.toString(id)));
            testSuccess(response);

        } catch (IOException e) {
            throw new MassaException("Encoding exception", e);
        } catch (Exception e) {
            throw new MassaException("DB exception: updateCert :", e);
        }

    }
}
