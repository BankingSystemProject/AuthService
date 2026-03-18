package sit.tuvarna.bg.authservice.web.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import io.vavr.control.Either;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import sit.tuvarna.bg.authservice.model.dto.AuthError;
import sit.tuvarna.bg.authservice.service.TokenService;
import sit.tuvarna.bg.authservice.web.dto.requests.BlacklistRequest;
import sit.tuvarna.bg.authservice.web.dto.requests.IssueRequest;
import sit.tuvarna.bg.authservice.web.dto.requests.RefreshRequest;
import sit.tuvarna.bg.authservice.web.dto.requests.ValidateRequest;
import sit.tuvarna.bg.authservice.web.dto.responses.MessageResponse;
import sit.tuvarna.bg.authservice.web.dto.responses.TokenPairResponse;
import sit.tuvarna.bg.authservice.web.dto.responses.ValidateResponse;


@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@Tag(name = "Token Controller", description = "Managing jwt tokens")
public class TokenController extends BaseController {

    private final TokenService tokenService;

    // ------------------------------------------------------------
    //  /issue  — requires internal API key
    // ------------------------------------------------------------
    @Operation(
            summary = "Issues jwt token pair",
            description = "Creates refresh and access token.Requires X-Internal-Api-Key header.",
            security = @SecurityRequirement(name = "internalApiKey")
    )
    @ApiResponses({
            @ApiResponse(responseCode = "201", description = "Tokens successfully issued",content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE)),
            @ApiResponse(responseCode = "400", description = "Invalid request body",content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE)),
            @ApiResponse(responseCode = "401", description = "Missing or invalid internal API key",content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE)),
            @ApiResponse(responseCode = "500", description = "Unexpected server error",content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE))
    })
    @PostMapping("/issue")
    public ResponseEntity<?> issue(@Valid @RequestBody IssueRequest request) {
        Either<AuthError, TokenPairResponse> issue = tokenService.issue(request);
        return handleResponse(issue, HttpStatus.CREATED, error -> switch (error.getCode()) {
            case BAD_BODY -> HttpStatus.BAD_REQUEST;      // 400
            case BAD_API_KEY -> HttpStatus.UNAUTHORIZED;  // 401 (rare, filter usually handles)
            case UNEXPECTED_ERROR -> HttpStatus.INTERNAL_SERVER_ERROR; // 500
            default -> HttpStatus.BAD_REQUEST;
        });
    }

    // ------------------------------------------------------------
    //  /validate  — public
    // ------------------------------------------------------------
    @Operation(
            summary = "Validate access token",
            description = "Validates an access token and returns its claims."
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Token is valid",content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE)),
            @ApiResponse(responseCode = "400", description = "Invalid request body",content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE)),
            @ApiResponse(responseCode = "401", description = "Token expired, blacklisted, or invalid",content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE))
    })
    @PostMapping("/validate")
    public ResponseEntity<?> validate(@Valid @RequestBody ValidateRequest request) {
        Either<AuthError, ValidateResponse> validate = tokenService.validate(request);

        return handleResponse(
                validate,
                HttpStatus.OK,
                error -> HttpStatus.UNAUTHORIZED //401 for expired/blacklisted token
        );
    }


    // ------------------------------------------------------------
    //  /refresh  — public
    // ------------------------------------------------------------
    @Operation(
            summary = "Refresh JWT tokens",
            description = "Exchanges a valid refresh token for a new access + refresh token pair."
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Tokens successfully refreshed",content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE)),
            @ApiResponse(responseCode = "400", description = "Malformed or invalid refresh token",content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE)),
            @ApiResponse(responseCode = "401", description = "Refresh token expired or blacklisted",content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE))
    })
    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@Valid @RequestBody RefreshRequest request) {
        Either<AuthError, TokenPairResponse> result = tokenService.refresh(request);
        return handleResponse(
                result,
                HttpStatus.OK,
                error -> switch (error.getCode()) {
                    case BAD_REFRESH_TOKEN -> HttpStatus.BAD_REQUEST; // 400
                    case INVALID_TOKEN -> HttpStatus.UNAUTHORIZED; // 401
                    default -> HttpStatus.BAD_REQUEST;
                }
        );
    }

    // ------------------------------------------------------------
    //  /blacklist  — requires valid access token
    // ------------------------------------------------------------
    @Operation(
            summary = "Blacklist a refresh token",
            description = "Marks a refresh token as blacklisted. Requires a valid Bearer access token.",
            security = @SecurityRequirement(name = "bearerAuth")
    )
    @ApiResponses({
            @ApiResponse(responseCode = "202", description = "Token successfully blacklisted",content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE)),
            @ApiResponse(responseCode = "400", description = "Malformed or invalid refresh token",content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE)),
            @ApiResponse(responseCode = "401", description = "Missing or invalid access token",content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE) )
    })
    @PostMapping("/blacklist")
    public ResponseEntity<?> blacklist(@Valid @RequestBody BlacklistRequest request) {
        Either<AuthError, MessageResponse> result = tokenService.blacklist(request);

        return handleResponse(result,
                HttpStatus.ACCEPTED, // 202
                error -> switch (error.getCode()) {
                    case UNAUTHENTICATED -> HttpStatus.UNAUTHORIZED; // 401
                    case MALFORMED_TOKEN -> HttpStatus.BAD_REQUEST; // 400
                    default -> HttpStatus.BAD_REQUEST;
                }
        );
    }
}
