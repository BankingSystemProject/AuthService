package sit.tuvarna.bg.authservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.scheduling.annotation.EnableScheduling;
import sit.tuvarna.bg.authservice.config.InternalApiKeyProperties;

@SpringBootApplication
@EnableCaching
@EnableScheduling
public class AuthServiceApplication {

    public static void main(String[] args) {
        ConfigurableApplicationContext run = SpringApplication.run(AuthServiceApplication.class, args);
        InternalApiKeyProperties bean = run.getBean(InternalApiKeyProperties.class);
        System.out.println(bean.getApiKey());

    }

}
