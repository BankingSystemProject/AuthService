package sit.tuvarna.bg.authservice.web.dto.requests;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import lombok.*;

import java.util.Set;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class IssueRequest {
    @NotBlank(message = "userId is required")
    private String userId;

    @NotBlank(message = "username is required")
    private String username;

    @NotEmpty(message = "At least one role is required")
    private Set<String> roles;

}

