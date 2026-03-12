package sit.tuvarna.bg.authservice.web.dto.responses;

import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class MessageResponse {
    private boolean success;
    private String message;
}
