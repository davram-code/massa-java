package ro.massa.db.impl;

import org.certificateservices.custom.c2x.common.Encodable;
import org.json.JSONObject;
import org.springframework.util.Base64Utils;
import ro.massa.common.MassaLog;
import ro.massa.common.MassaLogFactory;
import ro.massa.exception.MassaException;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.util.Calendar;
import java.util.Date;

public abstract class MassaDaoImpl {
    static protected MassaLog log = MassaLogFactory.getLog(MassaDaoImpl.class);

    protected byte[] getBytes(Encodable encodable) {

        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(baos);
            encodable.encode(dos);
            byte[] data = baos.toByteArray();
            return data;
        } catch (Exception e) {
            log.log(e.toString());
            return new byte[]{};
        }
    }

    protected String base64(Encodable encodable) {
        return base64(getBytes(encodable));
    }

    protected String base64(byte[] data) {
        if (data.length > 0)
            return new String(Base64Utils.encode(data));
        else
            return "null"; //TODO
    }

    protected void testSuccess(JSONObject jsonObject) throws MassaException {
        if (!jsonObject.getString("success").equals("true")) {
            throw new MassaException("DB Exception: " + jsonObject.toString());
        }
    }

    protected Date addYearsToDate(Date date, int years) {
        Calendar c = Calendar.getInstance();
        c.setTime(date);
        c.add(Calendar.YEAR, years);
        return c.getTime();
    }
}
