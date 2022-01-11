package ro.massa.db.impl;

import com.fasterxml.jackson.annotation.JsonTypeInfo;
import org.json.JSONObject;
import ro.massa.db.DatabaseClient;
import ro.massa.db.IAuthorizationAuthorityDao;
import ro.massa.db.types.AaStatus;
import ro.massa.db.types.CurveType;
import ro.massa.db.types.RequestStatus;
import ro.massa.exception.DbException;
import ro.massa.exception.DecodeEncodeException;
import ro.massa.its.AuthorizationAuthority;


public class AuthorizationAuthorityDaoImpl extends MassaDaoImpl implements IAuthorizationAuthorityDao {



    @Override
    public String insert(AuthorizationAuthority ar) throws DbException {
        try{
            JSONObject jsonPayload = new JSONObject()
                    .put("name", ar.getName())
                    .put("description", ar.getDescription())
                    .put("keyname", "keyname") //TODO
                    .put("pp", base64(ar.getPP()))
                    .put("curve_id", new CurveType(ar.getSignatureScheme()).getValue())
                    .put("certificate", base64(ar.getSelfCertificate()));
//                .put("aa_status_id", id from ct_aa_status table)
//                .put("engine_id", id from engine table)
//                .put("register_date", "date")
//                .put("end_date", "date")
//                .put("operator_id", id from operator table);
        }
        catch (DecodeEncodeException e)
        {
            throw new DbException("Insert Exception", e);
        }

        return "UniqueID";
    }

    private void changeAaStatus(String id, AaStatus status)
    {
        JSONObject jsonPayload = new JSONObject()
                .put("id", id)
                .put("aa_status_id", status);

        DatabaseClient.sendDatabaseMessage("PUT", "/aa/aa", jsonPayload);
    }

    @Override
    public void changeAaStatusToPending(String id)
    {
        changeAaStatus(id, AaStatus.pending);
    }

    @Override
    public void changeAaStatusToActive(String id)
    {
        changeAaStatus(id, AaStatus.active);
    }

    @Override
    public void changeAaStatusToInactive(String id)
    {
        changeAaStatus(id, AaStatus.inactive);
    }
}

