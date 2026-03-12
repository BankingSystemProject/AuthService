package sit.tuvarna.bg.authservice.web.dto.responses;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.*;

import java.time.Instant;
import java.util.Set;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ValidateResponse {
    private boolean valid;
    private String message;
    // Populated only when valid=true
    private String userId;
    private String username;
    private Set<String> roles;
    private String tokenId;
    private String  tokenType;  // "access" | "refresh"
    private Instant issuedAt;
    private Instant expiresAt;

}
