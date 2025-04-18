// File: src/main/java/org/example/iam/security/CustomOAuth2AuthenticationFailureHandler.java
package org.example.iam.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

/**
 * Handles failed OAuth2 authentications.
 * Redirects the user to a predefined error URL with appropriate error codes.
 */
@Component // Register as a Spring Bean
@Slf4j
public class CustomOAuth2AuthenticationFailureHandler implements AuthenticationFailureHandler {

    // Target URL for OAuth2 login failures (e.g., frontend login page with error)
    // Can be externalized to application.properties
    @Value("${app.oauth2.failure-redirect-url:/login?error}") // Default to login page with generic error
    private String targetUrl;

    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    /**
     * Called when an OAuth2 authentication attempt fails.
     * Logs the error and redirects the user to the failure URL with an error code.
     *
     * @param request   the request during which the authentication attempt occurred.
     * @param response  the response.
     * @param exception the exception which was thrown to reject the authentication
     * request.
     * @throws IOException      on input/output errors
     * @throws ServletException on servlet errors
     */
    @Override
    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationException exception) throws IOException, ServletException {

        log.warn("OAuth2 Authentication Failure: {}", exception.getMessage(), exception);

        String errorCode = "oauth2_generic_error"; // Default error code

        // Try to get a more specific error code from the exception
        if (exception instanceof OAuth2AuthenticationException oauth2Exception) {
            errorCode = oauth2Exception.getError().getErrorCode();
            // You could map standard OAuth2 error codes to custom ones if needed
            // switch (errorCode) {
            //     case OAuth2ErrorCodes.ACCESS_DENIED: errorCode = "oauth2_access_denied"; break;
            //     // Add other mappings...
            //     default: errorCode = "oauth2_provider_error"; break;
            // }
            log.info("OAuth2 specific error code: {}", errorCode);
        } else {
            // Handle potential internal errors during JIT provisioning etc.
            // These might be wrapped AuthenticationServiceException from the converter
            // Provide a generic code but log the specific internal error
            errorCode = "oauth2_internal_error";
            log.error("Non-OAuth2 exception during OAuth2 flow: {}", exception.getClass().getName());
        }


        if (response.isCommitted()) {
            log.debug("Response has already been committed. Unable to redirect to {}", targetUrl);
            return;
        }

        // Build target URL with error parameter
        String redirectUrl = UriComponentsBuilder.fromUriString(targetUrl)
                .queryParam("oauth2_error", errorCode) // Add error code as query param
                .build().toUriString();

        log.debug("Redirecting failed OAuth2 authentication attempt to URL: {}", redirectUrl);
        redirectStrategy.sendRedirect(request, response, redirectUrl);
    }
}