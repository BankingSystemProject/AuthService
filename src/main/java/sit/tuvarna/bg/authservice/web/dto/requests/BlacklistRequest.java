package sit.tuvarna.bg.authservice.web.dto.requests;

import jakarta.validation.constraints.NotBlank;
import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class BlacklistRequest {
    @NotBlank(message = "token is required")
    private String token;

    /** Optional human-readable reason, e.g. "logout", "password_changed". */
    private String reason;
}
