package sit.tuvarna.bg.authservice.web.controller;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.data.util.Pair;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import sit.tuvarna.bg.authservice.service.JwtService;
import sit.tuvarna.bg.authservice.service.QrCodeService;
import sit.tuvarna.bg.authservice.service.TotpService;
import sit.tuvarna.bg.authservice.web.dto.responses.TwoFactorSetupResponse;
import sit.tuvarna.bg.authservice.feign.UserServiceClient;
import sit.tuvarna.bg.authservice.web.dto.requests.TwoFactorVerifyRequest;

import java.util.Base64;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/2fa")
@RequiredArgsConstructor
public class TwoFactorController {

    private final TotpService totpService;
    private final QrCodeService qrCodeService;
    private final JwtService jwtService;
    private final UserServiceClient userServiceClient;

    @PostMapping("/setup")
    public ResponseEntity<TwoFactorSetupResponse> setup2fa(HttpServletRequest request) {

        Pair<String, UUID> pair = extractTokenAndUserId(request);
        if (pair == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        String username = jwtService.extractUsername(pair.getFirst());

        String secret = totpService.generateSecret();
        String otpauthUrl = totpService.buildOtpAuthUrl(username, secret);

        userServiceClient.storeTwoFactorSecret(pair.getSecond(), secret);

        byte[] qrPng = qrCodeService.generateQrCode(otpauthUrl, 300, 300);
        String base64 = Base64.getEncoder().encodeToString(qrPng);

        TwoFactorSetupResponse response = TwoFactorSetupResponse.builder()
                .otpauthUrl(otpauthUrl)
                .qrImageBase64(base64)
                .build();

        return ResponseEntity.ok(response);
    }

    @PostMapping("/verify")
    public ResponseEntity<String> postString(HttpServletRequest request, @RequestBody TwoFactorVerifyRequest verifyRequest) {

        UUID userId = extractTokenAndUserId(request).getSecond();
        String secret = userServiceClient.getTwoFactorSecret(userId);
        boolean valid = totpService.verifyCode(secret, verifyRequest.getCode());
        if (!valid) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        userServiceClient.enableTwoFactor(userId);
        return ResponseEntity.ok().build();
    }

    private Pair<String, UUID> extractTokenAndUserId(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith("Bearer ")) {
            return null;
        }
        String token = header.substring(7);
        UUID userId = UUID.fromString(jwtService.extractUserId(token));
        return Pair.of(token, userId);
    }
}
