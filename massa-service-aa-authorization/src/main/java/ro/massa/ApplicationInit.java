package ro.massa;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.stereotype.Component;
import ro.massa.common.MassaLog;
import ro.massa.common.MassaLogFactory;


@Component
@EnableScheduling
public class ApplicationInit implements ApplicationRunner {
    private MassaLog log = MassaLogFactory.getLog(ApplicationInit.class);
    private static final Logger LOG = LoggerFactory.getLogger(ApplicationInit.class);

    @Override
    public void run(ApplicationArguments args) throws Exception {
        log.log("Initializing MASSA");
        return;
    }
}
