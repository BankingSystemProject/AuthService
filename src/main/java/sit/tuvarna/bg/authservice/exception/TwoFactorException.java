package sit.tuvarna.bg.authservice.exception;

/**
 * Exception thrown when 2FA setup or verification fails.
 * This includes QR code generation, secret storage, and TOTP verification.
 */
public class TwoFactorException extends RuntimeException {

    public TwoFactorException(String message, Throwable cause) {
        super(message, cause);
    }
}

