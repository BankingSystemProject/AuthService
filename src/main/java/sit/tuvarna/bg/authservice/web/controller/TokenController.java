package sit.tuvarna.bg.authservice.web.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import sit.tuvarna.bg.authservice.service.TokenService;
import sit.tuvarna.bg.authservice.web.dto.requests.BlacklistRequest;
import sit.tuvarna.bg.authservice.web.dto.requests.IssueRequest;
import sit.tuvarna.bg.authservice.web.dto.requests.RefreshRequest;
import sit.tuvarna.bg.authservice.web.dto.requests.ValidateRequest;
import sit.tuvarna.bg.authservice.web.dto.responses.MessageResponse;
import sit.tuvarna.bg.authservice.web.dto.responses.TokenPairResponse;
import sit.tuvarna.bg.authservice.web.dto.responses.ValidateResponse;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@Tag(name = "Token Controller",description = "Managing jwt tokens")
public class TokenController {

    private final TokenService tokenService;


    /**
     * POST /api/v1/tokens/issue
     * Issue a token pair for a user who has already been authenticated by the user-service.
     *
     * Security: requires X-Internal-Api-Key header (enforced by InternalApiKeyFilter).
     *
     * Example request:
     * {
     *   "userId":   "550e8400-e29b-41d4-a716-446655440000",
     *   "username": "john",
     *   "roles":    ["ROLE_USER"]
     * }
     */
    @Operation(
            summary = "Issues jwt tokens",
            description = "Creates refresh and access token",
            security = @SecurityRequirement(name = "internalApiKey")
    )
    @PostMapping("/issue")
    public ResponseEntity<TokenPairResponse> issue(
            @Valid @RequestBody IssueRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(tokenService.issue(request));
    }

    /**
     * POST /api/v1/tokens/validate
     * Validate any token (access or refresh) and return its decoded claims.
     * Returns HTTP 200 in all cases; inspect the `valid` field in the body.
     *
     * Security: public — the caller doesn't need to be authenticated.
     *
     * Example request:
     * { "token": "<jwt>" }
     */
    @PostMapping("/validate")
    public ResponseEntity<ValidateResponse> validate(
            @Valid @RequestBody ValidateRequest request) {
        return ResponseEntity.ok(tokenService.validate(request));
    }

    /**
     * POST /api/v1/tokens/refresh
     * Exchange a valid, non-blacklisted refresh token for a new token pair (rotation).
     *
     * Security: public (caller provides the refresh token as proof of identity).
     *
     * Example request:
     * { "refreshToken": "<jwt>" }
     */
    @PostMapping("/refresh")
    public ResponseEntity<TokenPairResponse> refresh(
            @Valid @RequestBody RefreshRequest request) {
        return ResponseEntity.ok(tokenService.refresh(request));
    }

    /**
     * POST /api/v1/tokens/blacklist
     * Blacklist a specific token so it can no longer be used.
     *
     * Security: requires a valid Bearer token in Authorization header
     *           (the caller must be authenticated — enforced by SecurityConfig).
     *
     * Example request:
     * { "token": "<jwt>", "reason": "logout" }
     */
    @PostMapping("/blacklist")
    public ResponseEntity<MessageResponse> blacklist(
            @Valid @RequestBody BlacklistRequest request) {
        return ResponseEntity.ok(tokenService.blacklist(request));
    }

}
