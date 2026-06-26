package sit.tuvarna.bg.authservice.web.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import sit.tuvarna.bg.authservice.exception.AuthError;
import sit.tuvarna.bg.authservice.exception.TwoFactorException;
import sit.tuvarna.bg.authservice.web.dto.responses.ValidationErrorResponse;
import sit.tuvarna.bg.authservice.web.dto.responses.SimpleErrorResponse;

import java.util.List;

/**
 * Global exception handler for the Auth Service.
 * Handles all exceptions thrown in the service layer and converts them to appropriate HTTP responses.
 *
 * Exception Handling Strategy:
 * 1. AuthError - Authentication/Authorization failures → HTTP status based on error code
 * 2. MethodArgumentNotValidException - Validation errors → 400 with field-level details
 * 3. TwoFactorException - 2FA setup/verification failures → 500
 * 4. ExternalServiceException - Service-to-service communication failures → 503
 * 5. Generic Exception - Unexpected errors → 500
 */
@Slf4j
@ControllerAdvice
public class GlobalExceptionHandler {

    /**
     * Handles custom AuthError exceptions from the service layer.
     * Maps error codes to appropriate HTTP status codes.
     *
     * @param ex AuthError with error code and message
     * @return ResponseEntity with appropriate HTTP status and error details
     */
    @ExceptionHandler(AuthError.class)
    public ResponseEntity<AuthError> handleAuthException(AuthError ex) {
        log.warn("AuthError caught: {} - {}", ex.getCode(), ex.getMessage());

        HttpStatus status = switch (ex.getCode()) {
            case BAD_API_KEY, BLACKLISTED_TOKEN, UNAUTHENTICATED -> HttpStatus.UNAUTHORIZED;
            default -> HttpStatus.BAD_REQUEST;
        };

        return ResponseEntity.status(status)
                .body(new AuthError(ex.getCode(), ex.getMessage()));
    }

    /**
     * Handles validation errors from @Valid annotation on request bodies.
     * Extracts field-level validation errors and returns them in a list.
     *
     * @param ex MethodArgumentNotValidException with binding results
     * @return ResponseEntity with 400 status and list of validation errors
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ValidationErrorResponse> handleValidationException(MethodArgumentNotValidException ex) {
        log.warn("Validation error: {} field(s) failed validation", ex.getBindingResult().getErrorCount());

        List<String> messages = ex.getBindingResult()
                .getFieldErrors()
                .stream()
                .map(err -> err.getField() + ": " + err.getDefaultMessage())
                .toList();

        ValidationErrorResponse error = new ValidationErrorResponse(messages);

        return ResponseEntity.badRequest().body(error);
    }

    /**
     * Handles 2FA-related exceptions.
     * These typically indicate system errors in QR code generation, secret storage, etc.
     *
     * @param ex TwoFactorException with failure details
     * @return ResponseEntity with 500 status and error message
     */
    @ExceptionHandler(TwoFactorException.class)
    public ResponseEntity<SimpleErrorResponse> handle2FAException(TwoFactorException ex) {
        log.error("2FA Exception caught: {}", ex.getMessage(), ex);

        SimpleErrorResponse error = new SimpleErrorResponse(
                "TWO_FACTOR_ERROR",
                ex.getMessage()
        );

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
    }

    /**
     * Catch-all exception handler for any unexpected exceptions.
     * Logs the full error and returns a generic error response to the client.
     *
     * @param ex Any exception not caught by specific handlers
     * @return ResponseEntity with 500 status and generic error message
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<SimpleErrorResponse> handleGenericException(Exception ex) {
        log.error("Unexpected exception caught: ", ex);

        SimpleErrorResponse error = new SimpleErrorResponse(
                "UNEXPECTED_ERROR",
                "An unexpected error occurred. Please try again later."
        );

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
    }
}
