package sit.tuvarna.bg.authservice.service;

import io.jsonwebtoken.Claims;
import io.vavr.control.Either;
import io.vavr.control.Try;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import sit.tuvarna.bg.authservice.blacklistedToken.service.BlacklistedTokenService;
import sit.tuvarna.bg.authservice.exception.AuthError;
import sit.tuvarna.bg.authservice.enums.AuthErrorCode;
import sit.tuvarna.bg.authservice.feign.UserServiceClient;
import sit.tuvarna.bg.authservice.web.dto.requests.BlacklistRequest;
import sit.tuvarna.bg.authservice.web.dto.requests.IssueRequest;
import sit.tuvarna.bg.authservice.web.dto.requests.RefreshRequest;
import sit.tuvarna.bg.authservice.web.dto.requests.ValidateRequest;
import sit.tuvarna.bg.authservice.web.dto.responses.MessageResponse;
import sit.tuvarna.bg.authservice.web.dto.responses.TokenPairResponse;
import sit.tuvarna.bg.authservice.web.dto.responses.ValidateResponse;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class TokenService {

    private final JwtService jwtService;
    private final BlacklistedTokenService blacklistService;
    private final UserServiceClient userServiceClient;

    public Either<AuthError,TokenPairResponse> issue(IssueRequest req) {

        String accessToken = jwtService.generateAccessToken(req.getUserId(), req.getUsername(), req.getRoles());
        String refreshToken = jwtService.generateRefreshToken(req.getUserId(), req.getUsername());

        log.info("Issued token pair for userId={} username={}", req.getUserId(), req.getUsername());

        return Either.right(TokenPairResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .accessExpiresIn(jwtService.accessExpiresInSeconds())
                .refreshExpiresIn(jwtService.refreshExpiresInSeconds())
                .build());
    }

    public Either<AuthError, ValidateResponse> validate(ValidateRequest req) {
        return Try.of(() -> {
            String token = req.getToken();
            if (!jwtService.isStructurallyValid(token)) {
                return Either.<AuthError, ValidateResponse>left(new AuthError(AuthErrorCode.INVALID_TOKEN,"Token is expired or has an invalid signature"));
            }
            if (blacklistService.isBlacklisted(token)) {
                return Either.<AuthError, ValidateResponse>left(new AuthError(AuthErrorCode.BLACKLISTED_TOKEN,"Token has been revoked"));
            }

            Claims claims = jwtService.parseAllClaims(token);
            Set<String> roles = jwtService.extractRoles(claims);

            return Either.<AuthError, ValidateResponse>right(ValidateResponse.builder()
                    .valid(true)
                    .message("Token is valid")
                    .userId((String) claims.get("userId"))
                    .username(claims.getSubject())
                    .roles(roles)
                    .tokenId(claims.getId())
                    .tokenType((String) claims.get("type"))
                    .issuedAt(jwtService.extractIssuedAt(token))
                    .expiresAt(jwtService.extractExpiration(token))
                    .build());
        }).getOrElseGet(ex -> Either.left(new AuthError(AuthErrorCode.UNEXPECTED_ERROR,"Token validation failed due to an unexpected error: " + ex.getMessage())));
    }

    @Transactional
    public Either<AuthError, TokenPairResponse> refresh(RefreshRequest req) {
        return Try.of(() -> {
            String oldToken = req.getRefreshToken();

            if (!jwtService.isStructurallyValid(oldToken)) {
                return Either.<AuthError, TokenPairResponse>left(new AuthError(AuthErrorCode.INVALID_TOKEN,"Refresh token is expired or invalid"));
            }
            if (!"refresh".equals(jwtService.extractType(oldToken))) {
                return Either.<AuthError, TokenPairResponse>left(new AuthError(AuthErrorCode.BAD_REFRESH_TOKEN,"Provided token is not a refresh token"));
            }
            if (blacklistService.isBlacklisted(oldToken)) {
                return Either.<AuthError, TokenPairResponse>left(new AuthError(AuthErrorCode.BLACKLISTED_TOKEN,"Refresh token has been revoked"));
            }

            String userId = jwtService.extractUserId(oldToken);

            // Session-invalidation gate: reject refresh tokens issued before the user's
            // tokensValidFrom (bumped on password change). Compared at second granularity
            // because JWT iat has second precision. 0 = no gate.
            long validFromMillis = userServiceClient.getTokensValidFrom(UUID.fromString(userId));
            if (validFromMillis > 0) {
                Instant iat = jwtService.extractIssuedAt(oldToken);
                if (iat.getEpochSecond() < validFromMillis / 1000) {
                    return Either.<AuthError, TokenPairResponse>left(new AuthError(AuthErrorCode.INVALID_TOKEN,"Session invalidated; please log in again"));
                }
            }

            blacklistService.blacklist(oldToken, "token_rotation");

            String username = jwtService.extractUsername(oldToken);

            String newAccess = jwtService.generateAccessToken(userId, username, jwtService.extractRoles(jwtService.parseAllClaims(oldToken)));
            String newRefresh = jwtService.generateRefreshToken(userId, username);

            log.info("Rotated refresh token for userId={}", userId);

            return Either.<AuthError, TokenPairResponse>right(TokenPairResponse.builder()
                    .accessToken(newAccess)
                    .refreshToken(newRefresh)
                    .tokenType("Bearer")
                    .accessExpiresIn(jwtService.accessExpiresInSeconds())
                    .refreshExpiresIn(jwtService.refreshExpiresInSeconds())
                    .build());
        }).getOrElseGet(ex -> Either.left(new AuthError(AuthErrorCode.UNEXPECTED_ERROR,"Token refresh failed: " + ex.getMessage())));
    }

    public Either<AuthError, MessageResponse> blacklist(BlacklistRequest req) {
        return Try.of(() -> {
            blacklistService.blacklist(req.getToken(), req.getReason());
            return Either.<AuthError, MessageResponse>right(MessageResponse.builder().success(true).message("Token blacklisted").build());
        }).getOrElseGet(ex -> Either.left(new AuthError(AuthErrorCode.MALFORMED_TOKEN,"Token blacklisting failed: " + ex.getMessage())));
    }
}
