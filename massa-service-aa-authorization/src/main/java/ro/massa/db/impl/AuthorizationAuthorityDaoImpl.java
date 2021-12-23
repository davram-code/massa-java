package ro.massa.db.impl;

import org.json.JSONObject;
import ro.massa.db.IAuthorizationAuthorityDao;
import ro.massa.its.AuthorizationAuthority;
import ro.massa.properties.MassaProperties;

import java.util.Date;

public class AuthorizationAuthorityDaoImpl extends MassaDaoImpl implements IAuthorizationAuthorityDao {



    @Override
    public String insert(AuthorizationAuthority ar) {
        JSONObject jsonPayload = new JSONObject()
                .put("name", ar.getName())
                .put("description", ar.getDescription())
                .put("keyname", "keyname") //TODO
                .put("pp", base64(ar.getPP()));
//                .put("curve_id", id from ct_curve_type)
//                .put("certificate", null / "base64 value")
//                .put("aa_status_id", id from ct_aa_status table)
//                .put("engine_id", id from engine table)
//                .put("register_date", "date")
//                .put("end_date", "date")
//                .put("operator_id", id from operator table);

        return "UniqueID";
    }
}

