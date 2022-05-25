package ro.massa.db.impl;

import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.json.JSONObject;
import ro.massa.db.DatabaseClient;
import ro.massa.db.IEnrollmentDao;
import ro.massa.db.UrlQuerry;
import ro.massa.exception.MassaException;

public class EnrollmentDaoImpl extends MassaDaoImpl implements IEnrollmentDao {
    @Override
    public EtsiTs103097Certificate getEcCert(String signer) throws MassaException {
        try{
            while(signer.length() < 16){
                signer = "0" + signer;
            }
            UrlQuerry querry = new UrlQuerry().add("certificate_id", signer);
            JSONObject response = DatabaseClient.sendDatabaseMessage("GET", "/ea/enrolment", querry);
            String encodedCert = response.getString("certificate");
            return new EtsiTs103097Certificate(base64decode(encodedCert));
        }
        catch (Exception e)
        {
            throw new MassaException("Error getting EC form db", e);
        }

    }
}
