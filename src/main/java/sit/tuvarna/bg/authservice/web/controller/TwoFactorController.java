package sit.tuvarna.bg.authservice.web.controller;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.data.util.Pair;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import sit.tuvarna.bg.authservice.enums.AuthErrorCode;
import sit.tuvarna.bg.authservice.exception.AuthError;
import sit.tuvarna.bg.authservice.exception.TwoFactorException;
import sit.tuvarna.bg.authservice.feign.UserServiceClient;
import sit.tuvarna.bg.authservice.service.JwtService;
import sit.tuvarna.bg.authservice.service.QrCodeService;
import sit.tuvarna.bg.authservice.service.TotpService;
import sit.tuvarna.bg.authservice.web.dto.requests.TwoFactorVerifyRequest;
import sit.tuvarna.bg.authservice.web.dto.responses.TwoFactorSetupResponse;

import java.util.Base64;
import java.util.UUID;

/**
 * REST Controller for Two-Factor Authentication (2FA) operations.
 * Handles 2FA setup (TOTP secret generation and QR code) and verification.
 */
@RestController
@RequestMapping("/api/v1/2fa")
@RequiredArgsConstructor
public class TwoFactorController {

    private final TotpService totpService;
    private final QrCodeService qrCodeService;
    private final JwtService jwtService;
    private final UserServiceClient userServiceClient;

    /**
     * Setup 2FA by generating a TOTP secret and QR code.
     * Requires a valid JWT access token in the Authorization header.
     *
     * @param request HTTP request containing the Bearer token
     * @return TwoFactorSetupResponse with OTP Auth URL and QR code as base64
     * @throws AuthError if token is invalid or missing
     * @throws TwoFactorException if QR code generation or service calls fail
     */
    @PostMapping("/setup")
    public ResponseEntity<TwoFactorSetupResponse> setup2fa(HttpServletRequest request) {

        Pair<String, UUID> pair = extractTokenAndUserId(request);
        if (pair == null) {
            throw new AuthError(AuthErrorCode.UNAUTHENTICATED, "Missing or invalid Bearer token");
        }

        try {
            String username = jwtService.extractUsername(pair.getFirst());

            String secret = totpService.generateSecret();
            String otpauthUrl = totpService.buildOtpAuthUrl(username, secret);

            userServiceClient.storeTwoFactorSecret(pair.getSecond(), secret);

            byte[] qrPng = qrCodeService.generateQrCode(otpauthUrl, 300, 300);
            String base64 = Base64.getEncoder().encodeToString(qrPng);

            TwoFactorSetupResponse response = TwoFactorSetupResponse.builder()
                    .otpauthUrl(otpauthUrl)
                    .secret(secret)
                    .qrImageBase64(base64)
                    .build();

            return ResponseEntity.ok(response);
        } catch (AuthError ex) {
            // Re-throw AuthError to be handled by GlobalExceptionHandler
            throw ex;
        } catch (Exception ex) {
            // Wrap other exceptions in TwoFactorException
            throw new TwoFactorException("Failed to setup 2FA: " + ex.getMessage(), ex);
        }
    }

    /**
     * Verify a TOTP code and enable 2FA for the user.
     * Requires a valid JWT access token in the Authorization header.
     *
     * @param request HTTP request containing the Bearer token
     * @param verifyRequest containing the TOTP code
     * @return ResponseEntity with status OK if verification succeeds
     * @throws AuthError if token is invalid or verification fails
     * @throws TwoFactorException if external service calls fail
     */
    @PostMapping("/verify")
    public ResponseEntity<String> verify(HttpServletRequest request, @jakarta.validation.Valid @RequestBody TwoFactorVerifyRequest verifyRequest) {

        Pair<String, UUID> pair = extractTokenAndUserId(request);
        if (pair == null) {
            throw new AuthError(AuthErrorCode.UNAUTHENTICATED, "Missing or invalid Bearer token");
        }

        try {
            UUID userId = pair.getSecond();
            String secret = userServiceClient.getTwoFactorSecret(userId);

            boolean valid = totpService.verifyCode(secret, verifyRequest.getCode());
            if (!valid) {
                throw new AuthError(AuthErrorCode.INVALID_TOKEN, "Invalid TOTP code");
            }

            userServiceClient.enableTwoFactor(userId);
            return ResponseEntity.ok().build();
        } catch (AuthError ex) {
            // Re-throw AuthError to be handled by GlobalExceptionHandler
            throw ex;
        } catch (Exception ex) {
            // Wrap other exceptions in TwoFactorException
            throw new TwoFactorException("Failed to verify 2FA: " + ex.getMessage(), ex);
        }
    }

    /**
     * Extracts the JWT token and user ID from the Authorization header.
     *
     * @param request HTTP request
     * @return Pair of (token, userId) or null if header is missing/invalid
     */
    private Pair<String, UUID> extractTokenAndUserId(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith("Bearer ")) {
            return null;
        }
        String token = header.substring(7);
        try {
            UUID userId = UUID.fromString(jwtService.extractUserId(token));
            return Pair.of(token, userId);
        } catch (Exception e) {
            // Malformed/invalid token → treat as unauthenticated (never 500)
            throw new AuthError(AuthErrorCode.UNAUTHENTICATED, "Invalid or malformed token");
        }
    }
}
