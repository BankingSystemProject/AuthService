package sit.tuvarna.bg.authservice.web.dto.responses;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.List;

@Getter
@AllArgsConstructor
public class ValidationErrorResponse {
    private final String code = "BAD_BODY";
    private final List<String> messages;
}
