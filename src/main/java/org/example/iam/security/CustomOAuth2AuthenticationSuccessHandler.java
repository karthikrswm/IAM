// File: src/main/java/org/example/iam/security/CustomOAuth2AuthenticationSuccessHandler.java
package org.example.iam.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.example.iam.entity.User; // Assuming CustomOAuth2UserService sets local User as principal
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

/**
 * Handles successful OAuth2 authentications.
 * Redirects the user to a predefined target URL upon successful login,
 * relying on the session established during the OAuth2 flow.
 */
@Component // Register as a Spring Bean
@Slf4j
public class CustomOAuth2AuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    // Target URL after successful OAuth2 login (e.g., frontend dashboard)
    // Can be externalized to application.properties
    @Value("${app.oauth2.success-redirect-url:/}") // Default to root path
    private String targetUrl;

    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    /**
     * Called when a user has been successfully authenticated via OAuth2.
     * Performs redirection to the configured target URL.
     *
     * @param request        the request which caused the successful authentication
     * @param response       the response
     * @param authentication the <tt>Authentication</tt> object which was created during
     * the authentication process. Contains the principal (local User).
     * @throws IOException      on input/output errors
     * @throws ServletException on servlet errors
     */
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        String username = "<unknown>";
        if (authentication != null && authentication.getPrincipal() instanceof User localUser) {
            // Principal should be our local User entity after CustomOAuth2UserService runs
            username = localUser.getUsername();
            log.info("OAuth2 Authentication successful for local user: {}. Session ID: {}",
                    username, request.getSession(false) != null ? request.getSession(false).getId() : "<no session>");
        } else {
            log.warn("OAuth2 Authentication successful, but principal is not an instance of User: {}",
                    authentication != null ? authentication.getPrincipal().getClass().getName() : "null");
        }

        if (response.isCommitted()) {
            log.debug("Response has already been committed. Unable to redirect to {}", targetUrl);
            return;
        }

        // Clear any potential authentication attributes saved previously if needed
        // clearAuthenticationAttributes(request); // Usually handled by framework

        // Build target URL (could potentially add user-specific params if needed)
        String redirectUrl = UriComponentsBuilder.fromUriString(targetUrl)
                // Example: Add a query parameter if needed by the frontend
                // .queryParam("oauth2_login_success", "true")
                .build().toUriString();

        log.debug("Redirecting successfully authenticated OAuth2 user '{}' to target URL: {}", username, redirectUrl);
        redirectStrategy.sendRedirect(request, response, redirectUrl);
    }

    // Optional: Helper method to clear temporary authentication-related data stored in session
    /*
    protected void clearAuthenticationAttributes(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return;
        }
        session.removeAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
    }
    */
}