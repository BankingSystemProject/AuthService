package sit.tuvarna.bg.authservice.web.dto.requests;

import jakarta.validation.constraints.NotBlank;
import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ValidateRequest {
    @NotBlank(message = "token is required")
    private String token;
}
