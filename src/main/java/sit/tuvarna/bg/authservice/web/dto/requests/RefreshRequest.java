package sit.tuvarna.bg.authservice.web.dto.requests;

import jakarta.validation.constraints.NotBlank;
import lombok.*;


/**
 * Sent to exchange a refresh token for a new access token.
 */

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RefreshRequest {
    @NotBlank(message = "refreshToken is required")
    private String refreshToken;
}
