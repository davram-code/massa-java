package ro.massa;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;
import org.springframework.context.annotation.ComponentScan;
import ro.massa.properties.MassaProperties;

@ComponentScan(basePackages = {"ro.massa"})
@EnableConfigurationProperties({
        MassaProperties.class
})
@SpringBootApplication
public class MassaApplication extends SpringBootServletInitializer {
    public static void main(String[] args) {
        SpringApplication.run(MassaApplication.class, args);
    }
}
