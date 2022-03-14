package ro.massa.db.impl;

import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.camanagement.CaCertificateRequest;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.VerifyResult;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.json.JSONObject;
import ro.massa.db.DatabaseClient;
import ro.massa.db.ICaRequestDao;
import ro.massa.db.UrlQuerry;
import ro.massa.db.types.EntityType;
import ro.massa.db.types.RequestStatus;
import ro.massa.db.types.RequestType;
import ro.massa.exception.MassaException;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.Calendar;
import java.util.Date;

public class CaRequestDaoImpl extends MassaDaoImpl implements ICaRequestDao {

    private  RequestType requestType;
    private EntityType entityType;
    public CaRequestDaoImpl(RequestType requestType, EntityType entityType)
    {
        this.requestType = requestType;
        this.entityType = entityType;
    }


    @Override
    public int insert(VerifyResult<CaCertificateRequest> request) throws MassaException {

        log.log(request.getHeaderInfo().toString());

        JSONObject jsonPayload = new JSONObject()
                .put("requestdate", request.getHeaderInfo().getGenerationTime().asDate().toString())
                .put("requesttype_id", requestType.getValue())
                .put("entitytype_id", entityType.getValue())
                .put("requeststatus_id", RequestStatus.unprocessed.getValue())
                .put("certificate", "null")
                .put("certificate_id", -1)
                .put("eov", "1970-01-01")
                .put("receiveddate", new Date().toString())
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
                    .put("requeststatus_id", RequestStatus.certified.getValue())
                    .put("certificate", base64(certificate.getEncoded()))
                    .put("certificate_id", certificate.hashCode())
                    .put("eov", eov.toString())
                    .put("processeddate", new Date().toString())
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
