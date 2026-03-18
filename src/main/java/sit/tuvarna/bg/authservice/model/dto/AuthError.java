package sit.tuvarna.bg.authservice.model.dto;


import lombok.Getter;

@Getter
public class AuthError extends RuntimeException {
    private final AuthErrorCode code;

    public AuthError(AuthErrorCode code, String message){
        super(message);
        this.code=code;
    }
}
