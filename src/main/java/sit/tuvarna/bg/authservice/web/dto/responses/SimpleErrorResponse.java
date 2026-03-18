package sit.tuvarna.bg.authservice.web.dto.responses;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class SimpleErrorResponse {
    private String code;
    private String message;
}
