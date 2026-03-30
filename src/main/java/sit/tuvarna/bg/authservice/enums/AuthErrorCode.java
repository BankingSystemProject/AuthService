package sit.tuvarna.bg.authservice.enums;

public enum AuthErrorCode {
    BAD_API_KEY,
    BAD_BODY,
    BAD_REFRESH_TOKEN,
    INVALID_TOKEN,
    EXPIRED_TOKEN,
    BLACKLISTED_TOKEN,
    MALFORMED_TOKEN,
    UNAUTHENTICATED,
    UNEXPECTED_ERROR
}
