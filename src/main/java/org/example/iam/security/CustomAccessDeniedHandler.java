// File: src/main/java/org/example/iam/security/CustomAccessDeniedHandler.java
package org.example.iam.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.iam.api.ApiError; // Standard error response DTO
import org.example.iam.constant.ApiErrorMessages; // Standard error messages
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.OutputStream;

/**
 * Custom implementation of Spring Security's {@link AccessDeniedHandler}.
 * <p>
 * This handler is invoked when an authenticated user attempts to access a resource
 * for which they do not have sufficient permissions (authorization failure). This typically
 * occurs after successful authentication but failure during authorization checks
 * (e.g., based on roles via {@code @PreAuthorize} or request matchers).
 * </p>
 * <p>
 * It overrides the default behavior (which might be an error page or a simple 403 response)
 * to return a standardized {@link ApiError} response body in JSON format with an
 * HTTP {@link HttpStatus#FORBIDDEN} (403) status code.
 * </p>
 */
@Component // Mark as a Spring component so it can be injected into SecurityConfig
@RequiredArgsConstructor // Automatically creates constructor for final fields (ObjectMapper)
@Slf4j
public class CustomAccessDeniedHandler implements AccessDeniedHandler {

  /**
   * Jackson ObjectMapper for serializing the ApiError DTO to JSON.
   */
  private final ObjectMapper objectMapper;

  /**
   * Handles the {@link AccessDeniedException} thrown during the authorization process.
   * Sets the response status to 403 Forbidden and writes a standard {@link ApiError}
   * JSON body to the response.
   *
   * @param request               The request that resulted in an AccessDeniedException.
   * @param response              The response, so that the handler can modify it.
   * @param accessDeniedException The exception that caused the invocation.
   * @throws IOException      if an input or output error occurs during response writing.
   * @throws ServletException if a servlet error occurs.
   */
  @Override
  public void handle(HttpServletRequest request,
                     HttpServletResponse response,
                     AccessDeniedException accessDeniedException) throws IOException, ServletException {

    // Extract details for logging
    String requestUri = request.getRequestURI();
    // User should be authenticated at this point, but handle potential null principal defensively
    String username = (request.getUserPrincipal() != null) ? request.getUserPrincipal().getName() : "authenticated_user_unknown";

    log.warn("Access Denied: User '{}' attempted to access restricted path '{}'. Reason: {}",
            username, requestUri, accessDeniedException.getMessage());
    // Log full stack trace at DEBUG level if needed for deeper diagnosis
    // log.debug("AccessDeniedException details:", accessDeniedException);

    // Create the standard ApiError response for 403 Forbidden
    ApiError apiError = new ApiError(
            HttpStatus.FORBIDDEN,
            ApiErrorMessages.ACCESS_DENIED, // Use standard message
            requestUri
    );

    // Set response status and content type
    response.setStatus(HttpServletResponse.SC_FORBIDDEN); // 403 Forbidden
    response.setContentType(MediaType.APPLICATION_JSON_VALUE); // Content-Type: application/json

    // Write the ApiError JSON to the response output stream
    try (OutputStream out = response.getOutputStream()) {
      objectMapper.writeValue(out, apiError);
      log.debug("Sent 403 Forbidden ApiError response for path '{}'", requestUri);
    } catch (IOException e) {
      log.error("Error writing 403 Forbidden (Access Denied) response to output stream for path '{}'", requestUri, e);
      // Re-throw IO exception as we cannot recover here
      throw e;
    }
  }
}