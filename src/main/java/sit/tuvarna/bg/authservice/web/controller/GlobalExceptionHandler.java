package sit.tuvarna.bg.authservice.web.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import sit.tuvarna.bg.authservice.model.dto.AuthError;
import sit.tuvarna.bg.authservice.web.dto.responses.ValidationErrorResponse;

import java.util.List;

@ControllerAdvice
public class GlobalExceptionHandler {


    @ExceptionHandler(AuthError.class)
    public ResponseEntity<AuthError> handleAuthException(AuthError ex) {

        HttpStatus status = switch (ex.getCode()) {
            case BAD_API_KEY, BLACKLISTED_TOKEN, UNAUTHENTICATED -> HttpStatus.UNAUTHORIZED;
            default -> HttpStatus.BAD_REQUEST;
        };
        return ResponseEntity.status(status)
                .body(new AuthError(ex.getCode(), ex.getMessage()));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ValidationErrorResponse> handleValidationException(MethodArgumentNotValidException ex) {


        List<String> messages = ex.getBindingResult()
                .getFieldErrors()
                .stream()
                .map(err -> err.getField() + ": " + err.getDefaultMessage())
                .toList();

        ValidationErrorResponse error = new ValidationErrorResponse(messages);

        return ResponseEntity.badRequest().body(error);
    }
}
