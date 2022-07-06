package ro.massa.db.impl;

import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.json.JSONObject;
import ro.massa.common.Utils;
import ro.massa.its.SubCaData;
import ro.massa.rest.DatabaseClient;
import ro.massa.db.ICaDao;
import ro.massa.rest.UrlQuerry;
import ro.massa.exception.MassaException;
import ro.massa.its.ITSEntity;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public class CaDaoImpl extends MassaDaoImpl implements ICaDao {
    private String pp;
    private int operatorId;
    private EtsiTs103097Certificate certificate;
    private String description;
    private String name;
    private KeyPair encKeyPair;
    private KeyPair signKeyPair;

    private KeyPair getKeyPairFromJson(JSONObject json, String pubKey, String prvKey) throws Exception {
        PublicKey pub = Utils.readPublicKey(Utils.decodeBase64(json.getString(pubKey)));
        PrivateKey prv = Utils.readPrivateKey(Utils.decodeBase64(json.getString(prvKey)));
        return new KeyPair(pub, prv);
    }

    @Override
    public EtsiTs103097Certificate getCertificate() {
        return certificate;
    }

    public KeyPair getEncKeyPair() {
        return encKeyPair;
    }

    public KeyPair getSignKeyPair() {
        return signKeyPair;
    }

    public SubCaData getSubCaData() {return new SubCaData(name, 10);}


    @Override
    public int loadCa(int id) throws MassaException {

        //JSONObject response = databaseClient.sendDatabaseMessage("GET", "/ea/ea", new UrlQuerry().add("id", Integer.toString(id)));
        JSONObject response = databaseClient.sendDatabaseMessage("GET", "/aa/aa", new UrlQuerry().add("id", Integer.toString(id)));
        try {
            certificate = new EtsiTs103097Certificate(Utils.decodeBase64(response.getString("certificate")));
        } catch (Exception e) {
            log.log("Could not decode certificate from db: " + e.getMessage()); // in cazul in care in baza de date nu exista un certificat
            certificate = null;
        }
        description = response.getString("description");
        name = response.getString("name");
        try {
            signKeyPair = getKeyPairFromJson(response, "sgn_pub_key", "sgn_prv_key");
            encKeyPair = getKeyPairFromJson(response, "enc_pub_key", "enc_prv_key");
        } catch (Exception e) {
            log.log("Exception reading keys from DB: " + e.getMessage());
        }
        testSuccess(response);
        return 0;
    }

    public void genDebugKeys() throws Exception {
        ITSEntity e = new ITSEntity();
        KeyPair kpe = e.generateEncKeyPair();


        log.log("KEYS:");
        log.log(base64(kpe.getPublic().getEncoded()));
        log.log(base64(kpe.getPrivate().getEncoded()));


        KeyPair kps = e.generateSignKeyPair();
        log.log(base64(kps.getPublic().getEncoded()));
        log.log(base64(kps.getPrivate().getEncoded()));
    }


    @Override
    public void updateCert() throws Exception {
        JSONObject response = databaseClient.sendDatabaseMessage("GET", "/ea/ea", new UrlQuerry().add("id", 7));
        log.log("EA data:");
        log.log(response.toString());
    }

}
