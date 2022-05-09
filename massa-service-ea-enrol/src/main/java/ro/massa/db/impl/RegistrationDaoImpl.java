package ro.massa.db.impl;


import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.enrollment.InnerEcRequest;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.RequestVerifyResult;
import org.json.JSONObject;
import ro.massa.db.DatabaseClient;
import ro.massa.db.IRegistrationDao;
import ro.massa.db.UrlQuerry;
import ro.massa.exception.MassaException;

public class RegistrationDaoImpl  extends MassaDaoImpl implements IRegistrationDao  {
    @Override
    public boolean checkRegistration(RequestVerifyResult<InnerEcRequest> enrollmentRequest) throws MassaException {
        JSONObject response = DatabaseClient.sendDatabaseMessage("GET", "/ea/registration", new UrlQuerry().add("id", 11));
        return testSuccess(response);
    }
}
