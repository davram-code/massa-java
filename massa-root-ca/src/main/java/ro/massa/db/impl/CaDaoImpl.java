package ro.massa.db.impl;

import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.json.JSONObject;
import ro.massa.db.DatabaseClient;
import ro.massa.db.ICaDao;
import ro.massa.db.UrlQuerry;
import ro.massa.db.types.CaStatusType;
import ro.massa.db.types.CurveType;
import ro.massa.db.types.RequestStatus;
import ro.massa.exception.MassaException;

import java.util.Date;

public class CaDaoImpl extends MassaDaoImpl implements ICaDao {
    private String pp;
    private int operatorId;
    private EtsiTs103097Certificate certificate;
    private String description;
    private String name;
    private String keyname;

    @Override
    public EtsiTs103097Certificate getCertificate() {
        return certificate;
    }

    @Override
    public String getKeyLabels() {
        return keyname;
    }

    @Override
    public int loadCa(int id) throws MassaException {
        JSONObject response = DatabaseClient.sendDatabaseMessage("GET", "/rootca/ca", new UrlQuerry().add("id", Integer.toString(id)));
        pp = response.getString("pp");
        operatorId = response.getInt("operator_id");
        try {
            certificate = new EtsiTs103097Certificate(decodeBase64(response.getString("certificate")));
        } catch (Exception e) {
            log.log("Could not decode certificate from db: " + e.getMessage()); // in cazul in care in baza de date nu exista un certificat
            certificate = null;
        }
        description = response.getString("description");
        name = response.getString("name");
        keyname = response.getString("keyname");
        testSuccess(response);
        return 0;
    }

    @Override
    public void updateCert(int id, EtsiTs103097Certificate certificate, String keyname) throws Exception {
        Date eov = addYearsToDate(certificate.getToBeSigned().getValidityPeriod().getStart().asDate(),
                certificate.getToBeSigned().getValidityPeriod().getDuration().getValueAsInt());
        JSONObject jsonPayload = new JSONObject()
                .put("pp", pp)
                .put("operator_id", operatorId)
                .put("certificate", base64(certificate))
                .put("description", description)
                .put("registerdate", new Date().toString())
                .put("curve_id", CurveType.secp256r1.getValue())
                .put("ca_status_id", CaStatusType.active.getValue())
                .put("enddate", eov.toString())
                .put("engine_id", "21")
                .put("name", name)
                .put("keyname", keyname);

        JSONObject response = DatabaseClient.sendDatabaseMessage("PUT", "/rootca/ca", jsonPayload, new UrlQuerry().add("id", Integer.toString(id)));

        testSuccess(response);
    }
}
