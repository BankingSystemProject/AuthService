package sit.tuvarna.bg.authservice.exception;


import lombok.Getter;
import sit.tuvarna.bg.authservice.enums.AuthErrorCode;

@Getter
public class AuthError extends RuntimeException {
    private final AuthErrorCode code;

    public AuthError(AuthErrorCode code, String message){
        super(message);
        this.code=code;
    }
}
