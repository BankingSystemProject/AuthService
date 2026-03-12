package sit.tuvarna.bg.authservice.web.dto.responses;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class TokenPairResponse {
    private String accessToken;
    private String refreshToken;
    private String tokenType;
    private long accessExpiresIn;   // seconds
    private long refreshExpiresIn;  // seconds
}
