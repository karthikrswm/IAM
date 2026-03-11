// File: src/main/java/org/example/iam/security/ApiLogoutSuccessHandler.java
package org.example.iam.security; // Changed package slightly for generic security component

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.iam.api.ApiSuccessResponse;
import org.example.iam.constant.ApiResponseMessages;
import org.example.iam.constant.AuditEventType;
import org.example.iam.entity.User;
import org.example.iam.service.AuditEventService;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Component;
// Removed @Component, will define as @Bean in SecurityConfig
// import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.OutputStream;
import java.util.UUID;

/**
 * Custom LogoutSuccessHandler for API-based logouts (including SAML SLO).
 * <p>
 * This handler is invoked after Spring Security has successfully processed a logout request
 * (could be standard /logout or triggered by SAML SLO).
 * </p><p>
 * Instead of performing a redirect, this implementation:
 * 1. Invalidates the local HTTP session.
 * 2. Logs a success audit event.
 * 3. Returns a standard JSON success response (200 OK) to the client.
 * </p>
 */
@Component("apiLogoutSuccessHandler")
@RequiredArgsConstructor // Use constructor injection for dependencies
@Slf4j
public class ApiLogoutSuccessHandler implements LogoutSuccessHandler {

    private final AuditEventService auditEventService;
    private final ObjectMapper objectMapper;

    @Override
    public void onLogoutSuccess(HttpServletRequest request,
                                HttpServletResponse response,
                                Authentication authentication) // Authentication object MAY be null if logout happened before full auth
            throws IOException, ServletException {

        // Attempt to get username for logging/auditing, handle null authentication
        String username = "UNKNOWN_USER";
        UUID userId = null;
        UUID orgId = null;

        if (authentication != null && authentication.isAuthenticated()) {
            username = authentication.getName(); // Get name from existing auth if possible
            if (authentication.getPrincipal() instanceof User userPrincipal) {
                userId = userPrincipal.getId();
                orgId = userPrincipal.getOrganization() != null ? userPrincipal.getOrganization().getId() : null;
            } else if (authentication.getDetails() instanceof User userDetails) {
                username = userDetails.getUsername(); // Fallback if user in details
                userId = userDetails.getId();
                orgId = userDetails.getOrganization() != null ? userDetails.getOrganization().getId() : null;
            }
        } else {
            log.warn("[Logout Handler] Authentication object was null or not authenticated during logout success handling. Actor will be logged as UNKNOWN.");
        }

        log.info("[Logout Handler] Logout successful for user '{}'. Invalidating session and returning JSON response.", username);

        // 1. Invalidate local HTTP session
        HttpSession session = request.getSession(false); // Do not create if none exists
        if (session != null) {
            String sessionId = session.getId();
            log.debug("[Logout Handler] Invalidating local HTTP session: {}", sessionId);
            try {
                session.invalidate();
            } catch (IllegalStateException e) {
                log.warn("[Logout Handler] Attempted to invalidate an already invalidated session: {}", e.getMessage());
            }
        } else {
            log.debug("[Logout Handler] No local HTTP session found to invalidate.");
        }

        // 2. Log Audit Event (Use username if available, otherwise mark as potentially unknown)
        auditEventService.logEvent(
                AuditEventType.LOGOUT_SUCCESS,
                String.format("User '%s' logged out successfully", username),
                username, // Actor might be unknown if auth already cleared
                "SUCCESS",
                "USER", userId != null ? userId.toString() : username,
                orgId,
                "Logout processed successfully." // Details
        );

        // 3. Send JSON Response (No Redirect)
        if (!response.isCommitted()) {
            response.setStatus(HttpStatus.OK.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            ApiSuccessResponse<Void> apiResponse = ApiSuccessResponse.ok(ApiResponseMessages.LOGOUT_SUCCESS); // Use constant

            try (OutputStream out = response.getOutputStream()) {
                objectMapper.writeValue(out, apiResponse);
                log.debug("[Logout Handler] Responded with 200 OK JSON for logout success.");
            } catch (IOException e) {
                log.error("[Logout Handler] Error writing logout success JSON response: {}", e.getMessage(), e);
                throw e; // Re-throw IO exception
            }
        } else {
            log.warn("[Logout Handler] Response already committed before success handler could write JSON body.");
        }
    }
}