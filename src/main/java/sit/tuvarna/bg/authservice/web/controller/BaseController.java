package sit.tuvarna.bg.authservice.web.controller;

import io.vavr.control.Either;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import sit.tuvarna.bg.authservice.model.dto.AuthError;
import sit.tuvarna.bg.authservice.web.dto.responses.SimpleErrorResponse;

import java.util.function.Function;

public abstract class BaseController {

    public ResponseEntity<?> handleResponse(Either<AuthError, ?> result,
                                            HttpStatus successStatus,
                                            Function<AuthError, HttpStatus> errorMapper) {
        if (result.isRight()) {
            return ResponseEntity.status(successStatus).body(result.get());
        }

        AuthError left = result.getLeft();
        HttpStatus errorStatus = errorMapper.apply(left);
        SimpleErrorResponse error=new SimpleErrorResponse(
                errorStatus.toString(),
                left.getMessage()
        );

        return ResponseEntity.status(errorMapper.apply(result.getLeft()))
                .body(error);
    }
}
