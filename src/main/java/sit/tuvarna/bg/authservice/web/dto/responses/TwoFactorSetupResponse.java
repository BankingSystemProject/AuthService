package sit.tuvarna.bg.authservice.web.dto.responses;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class TwoFactorSetupResponse {
    private String otpauthUrl;   // for frontend to generate QR itself if needed
    private String secret;       // optional, usually not shown
    private String qrImageBase64; // PNG as base64 for direct display
}
