package sit.tuvarna.bg.authservice.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import sit.tuvarna.bg.authservice.blacklistedToken.service.BlacklistedTokenService;
import sit.tuvarna.bg.authservice.exception.TokenException;
import sit.tuvarna.bg.authservice.web.dto.requests.BlacklistRequest;
import sit.tuvarna.bg.authservice.web.dto.requests.IssueRequest;
import sit.tuvarna.bg.authservice.web.dto.requests.RefreshRequest;
import sit.tuvarna.bg.authservice.web.dto.requests.ValidateRequest;
import sit.tuvarna.bg.authservice.web.dto.responses.MessageResponse;
import sit.tuvarna.bg.authservice.web.dto.responses.TokenPairResponse;
import sit.tuvarna.bg.authservice.web.dto.responses.ValidateResponse;

import java.util.List;
import java.util.Set;

@Slf4j
@Service
@RequiredArgsConstructor
public class TokenService {

    private final JwtService jwtService;
    private final BlacklistedTokenService blacklistService;

    public TokenPairResponse issue(IssueRequest req) {
        String accessToken  = jwtService.generateAccessToken(req.getUserId(), req.getUsername(), req.getRoles());
        String refreshToken = jwtService.generateRefreshToken(req.getUserId(), req.getUsername());

        log.info("Issued token pair for userId={} username={}", req.getUserId(), req.getUsername());

        return TokenPairResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .accessExpiresIn(jwtService.accessExpiresInSeconds())
                .refreshExpiresIn(jwtService.refreshExpiresInSeconds())
                .build();
    }

    /**
     * Validate any token and return its decoded claims.
     * Always returns HTTP 200; inspect the `valid` field in the body.
     */
    public ValidateResponse validate(ValidateRequest req) {
        String token = req.getToken();

        if (!jwtService.isStructurallyValid(token)) {
            return invalid("Token is expired or has an invalid signature");
        }

        if (blacklistService.isBlacklisted(token)) {
            return invalid("Token has been revoked");
        }

        try {
            Claims claims = jwtService.parseAllClaims(token);

            @SuppressWarnings("unchecked")
            Set<String> roles = claims.get("roles") != null
                    ? Set.copyOf((List<String>) claims.get("roles"))
                    : Set.of();

            return ValidateResponse.builder()
                    .valid(true)
                    .message("Token is valid")
                    .userId((String) claims.get("userId"))
                    .username(claims.getSubject())
                    .roles(roles)
                    .tokenId(claims.getId())
                    .tokenType((String) claims.get("type"))
                    .issuedAt(jwtService.extractIssuedAt(token))
                    .expiresAt(jwtService.extractExpiration(token))
                    .build();
        } catch (JwtException e) {
            return invalid("Token validation failed");
        }
    }

    /**
     * Rotate a refresh token:
     *   1. Verify the old refresh token (signature, expiry, blacklist, type).
     *   2. Blacklist the old refresh token so it can't be reused.
     *   3. Issue and return a brand-new token pair.
     *
     * The new access token carries the same userId/username but NO roles —
     * roles are owned by the user-service. If you need roles in the rotated
     * access token, store them in the refresh token's claims or have the
     * API gateway call /issue with fresh roles after validating the refresh.
     */
    @Transactional
    public TokenPairResponse refresh(RefreshRequest req) {
        String oldToken = req.getRefreshToken();

        if (!jwtService.isStructurallyValid(oldToken)) {
            throw new TokenException("Refresh token is expired or invalid");
        }

        try {
            if (!"refresh".equals(jwtService.extractType(oldToken))) {
                throw new TokenException("Provided token is not a refresh token");
            }
        } catch (JwtException e) {
            throw new TokenException("Invalid token");
        }

        if (blacklistService.isBlacklisted(oldToken)) {
            throw new TokenException("Refresh token has been revoked");
        }

        // Blacklist old token — this is the revocation
        blacklistService.blacklist(oldToken, "token_rotation");

        String userId   = jwtService.extractUserId(oldToken);
        String username = jwtService.extractUsername(oldToken);

        String newAccess  = jwtService.generateAccessToken(userId, username, Set.of());
        String newRefresh = jwtService.generateRefreshToken(userId, username);

        log.info("Rotated refresh token for userId={}", userId);

        return TokenPairResponse.builder()
                .accessToken(newAccess)
                .refreshToken(newRefresh)
                .tokenType("Bearer")
                .accessExpiresIn(jwtService.accessExpiresInSeconds())
                .refreshExpiresIn(jwtService.refreshExpiresInSeconds())
                .build();
    }

    /**
     * Explicitly blacklist any token (access or refresh).
     * Callers use this for logout — send both tokens to fully terminate a session.
     */
    @Transactional
    public MessageResponse blacklist(BlacklistRequest req) {
        blacklistService.blacklist(req.getToken(), req.getReason());
        return MessageResponse.builder().success(true).message("Token blacklisted").build();
    }


    private ValidateResponse invalid(String message) {
        return ValidateResponse.builder().valid(false).message(message).build();
    }
}
