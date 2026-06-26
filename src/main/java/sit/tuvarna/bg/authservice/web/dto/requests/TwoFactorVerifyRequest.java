package sit.tuvarna.bg.authservice.web.dto.requests;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class TwoFactorVerifyRequest {
    // Boxed + validated: a missing/non-numeric body field must 400, not silently
    // become 0 and be submitted as a real TOTP attempt.
    @NotNull(message = "TOTP code is required")
    @Min(value = 0, message = "TOTP code must be a 6-digit number")
    @Max(value = 999999, message = "TOTP code must be a 6-digit number")
    private Integer code;
}