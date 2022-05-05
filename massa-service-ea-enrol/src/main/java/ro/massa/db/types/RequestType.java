package ro.massa.db.types;

import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.enrollment.InnerEcRequest;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.RequestVerifyResult;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.SignerIdentifier;

import javax.servlet.GenericFilter;

public class RequestType implements IMassaType {
    public enum RequestTypeValue {
        initial(0),
        rekey(1);

        private int value;

        private RequestTypeValue(int value) {
            this.value = value;
        }

        public int getValue() {
            return value;
        }
    }

    RequestTypeValue value;

    public RequestType(RequestVerifyResult<InnerEcRequest> enrollmentRequest) {
        if(enrollmentRequest.getSignerIdentifier().getType() == SignerIdentifier.SignerIdentifierChoices.self)
        {
            value = RequestTypeValue.initial;
        }
        else
        {
            value = RequestTypeValue.rekey;
        }
    }

    @Override
    public int getValue() {
        return value.getValue();
    }
}

