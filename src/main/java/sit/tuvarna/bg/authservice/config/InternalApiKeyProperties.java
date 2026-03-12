package sit.tuvarna.bg.authservice.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@Getter
@Setter
@ConfigurationProperties(prefix = "internal")
public class InternalApiKeyProperties {

    private String apiKey;
}
