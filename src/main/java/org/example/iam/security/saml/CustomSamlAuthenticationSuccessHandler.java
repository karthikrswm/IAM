// File: src/main/java/org/example/iam/security/saml/CustomSamlAuthenticationSuccessHandler.java
package org.example.iam.security.saml;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.iam.api.ApiSuccessResponse; // Import success wrapper
import org.example.iam.constant.ApiResponseMessages; // Import messages
import org.example.iam.constant.AuditEventType; // Import audit types
import org.example.iam.dto.UserResponse; // Import User DTO for response body
import org.example.iam.entity.Organization;
import org.example.iam.entity.User; // Assuming CustomSaml2AuthConverter sets local User as principal/details
import org.example.iam.service.AuditEventService; // Inject audit service
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.OutputStream;
import java.util.UUID;

/**
 * Custom AuthenticationSuccessHandler for SAML 2.0 Logins.
 * Returns a 200 OK with user details in JSON format instead of redirecting.
 * Relies on preceding filters (SessionRepositoryFilter, CsrfFilter with CookieCsrfTokenRepository)
 * to set the necessary session and CSRF cookies on the response object BEFORE this handler writes the body.
 * Logs success audit event.
 */
@Component("customSamlAuthenticationSuccessHandler")
@RequiredArgsConstructor // Use constructor injection
@Slf4j
public class CustomSamlAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final ObjectMapper objectMapper; // For writing JSON response
    private final AuditEventService auditEventService; // For logging audit

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        String username = "<unknown_principal>";
        UUID userId = null;
        UUID orgId = null;
        UserResponse userResponse = null;

        // Extract user details from the Authentication object
        // Assumes CustomSaml2AuthenticationConverter sets the local User entity as details or principal
        if (authentication != null && authentication.getPrincipal() instanceof User localUser) {
            // Option 1: Principal is the User entity directly (less common for Saml2Authentication)
            username = localUser.getUsername();
            userId = localUser.getId();
            orgId = localUser.getOrganization() != null ? localUser.getOrganization().getId() : null;
            userResponse = UserResponse.fromEntity(localUser); // Map to DTO
        } else if (authentication != null && authentication.getDetails() instanceof User localUser) {
            // Option 2: Principal is Saml2AuthenticatedPrincipal, Details is the User entity
            username = localUser.getUsername();
            userId = localUser.getId();
            orgId = localUser.getOrganization() != null ? localUser.getOrganization().getId() : null;
            userResponse = UserResponse.fromEntity(localUser); // Map to DTO
        } else if (authentication != null) {
            // Fallback if principal/details are not the User entity directly
            username = authentication.getName();
            log.warn("[SAML Success Handler] Principal/Details not instance of User entity for {}. Cannot include full details in response.", username);
            // Could potentially build a partial UserResponse from authentication.getName() and authentication.getAuthorities() if needed
        }


        log.info("[SAML Success Handler] Authentication successful for user: {}. Session ID: {}",
                username, request.getSession(false) != null ? request.getSession(false).getId() : "<no session yet?>");

        // --- Log Audit Event ---
        auditEventService.logEvent(
                AuditEventType.LOGIN_SUCCESS,
                String.format("User '%s' logged in successfully via SAML", username),
                username, "SUCCESS",
                "USER", userId != null ? userId.toString() : username, // Target is the user
                orgId,
                "SAML Authentication successful"
        );

        // --- Prepare JSON Response ---
        if (!response.isCommitted()) {
            response.setStatus(HttpStatus.OK.value()); // 200 OK
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);

            // Build success response body (including user details if available)
            ApiSuccessResponse<UserResponse> apiResponse = ApiSuccessResponse.ok(userResponse, ApiResponseMessages.LOGIN_SUCCESSFUL + " (SAML)");

            // Write JSON body
            try (OutputStream out = response.getOutputStream()) {
                objectMapper.writeValue(out, apiResponse);
                log.info("[SAML Success Handler] Responded with 200 OK JSON for SAML success for user '{}'.", username);
            } catch (IOException e) {
                log.error("[SAML Success Handler] Error writing success JSON response for user '{}': {}", username, e.getMessage(), e);
                throw e; // Re-throw IO exception
            }
            // By writing to the response, we implicitly prevent any default redirect handlers from acting.
        } else {
            log.debug("[SAML Success Handler] Response already committed, cannot send custom JSON response.");
        }
    }
}