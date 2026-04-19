package sit.tuvarna.bg.authservice.web.dto.requests;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class TwoFactorVerifyRequest {
    private int code;
}
