package ro.massa;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.stereotype.Component;
import ro.massa.ITSEntity;


@Component
@EnableScheduling
public class ApplicationInit implements ApplicationRunner {
    private static final Logger LOG = LoggerFactory.getLogger(ApplicationInit.class);

    @Override
    public void run(ApplicationArguments args) throws Exception {
        LOG.info("Init MASSA application...");

        ITSEntity EA = new ITSEntity();
        ITSEntity AA = new ITSEntity();

        System.out.println("EA is generating its key pairs...");
        EA.generateSignKeyPair("certificates/services/ea/SignPubKey.bin",
                "certificates/services/ea/SignPrvKey.bin");
        EA.generateEncKeyPair("certificates/services/ea/EncPubKey.bin",
                "certificates/services/ea/EncPrvKey.bin");

        System.out.println("AA is generating its key pairs...");
        AA.generateSignKeyPair("certificates/services/aa/SignKey.pub",
                "certificates/services/aa/SignKey.prv");
        AA.generateEncKeyPair("certificates/services/aa/EncKey.pub",
                "certificates/services/aa/EncKey.prv");

        return;



    }
}
