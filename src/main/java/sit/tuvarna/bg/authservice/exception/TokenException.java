package sit.tuvarna.bg.authservice.exception;

/**
 * Exception thrown when token-related operations fail.
 * This includes parsing, validation, expiration, and blacklist checks.
 */
public class TokenException extends RuntimeException {
    public TokenException(String message) {
        super(message);
    }

    public TokenException(String message, Throwable cause) {
        super(message, cause);
    }
}
