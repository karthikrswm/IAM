// File: src/main/java/org/example/iam/security/JwtAuthenticationEntryPoint.java
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
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.OutputStream;

/**
 * Custom implementation of Spring Security's {@link AuthenticationEntryPoint}.
 * <p>
 * This entry point is invoked when an unauthenticated client attempts to access a secured resource.
 * It's typically triggered when the {@link org.springframework.security.web.access.ExceptionTranslationFilter}
 * catches an {@link AuthenticationException} (indicating failed authentication or lack of credentials)
 * before accessing a protected endpoint.
 * </p>
 * <p>
 * Instead of redirecting to a login page (common in traditional web apps), this implementation
 * returns a standardized {@link ApiError} response body in JSON format with an
 * HTTP {@link HttpStatus#UNAUTHORIZED} (401) status code, suitable for RESTful APIs using
 * token-based authentication like JWT.
 * </p>
 */
@Component // Mark as a Spring component so it can be injected into SecurityConfig
@RequiredArgsConstructor // Automatically creates constructor for final fields (ObjectMapper)
@Slf4j
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

  /**
   * Jackson ObjectMapper for serializing the ApiError DTO to JSON.
   */
  private final ObjectMapper objectMapper;

  /**
   * Commences the authentication scheme. This method is called whenever an unauthenticated
   * user tries to access a secured resource and an AuthenticationException is thrown.
   * Sets the response status to 401 Unauthorized and writes a standard {@link ApiError}
   * JSON body to the response.
   *
   * @param request       The request that resulted in an AuthenticationException.
   * @param response      The response, so that the handler can modify it.
   * @param authException The exception that triggered this entry point.
   * @throws IOException      if an input or output error occurs during response writing.
   * @throws ServletException if a servlet error occurs.
   */
  @Override
  public void commence(HttpServletRequest request,
                       HttpServletResponse response,
                       AuthenticationException authException) throws IOException, ServletException {

    String requestUri = request.getRequestURI();
    // Log the authentication failure. The specific reason is in the exception message.
    log.warn("Authentication required or failed for path: {}. Error: {}", requestUri, authException.getMessage());
    // Log full stack trace at DEBUG level if needed
    // log.debug("AuthenticationException details for path [{}]:", requestUri, authException);

    // Determine the most appropriate error message.
    // Often, the exception occurs early (e.g., missing/malformed token) before specific credential checks.
    // ApiErrorMessages.INVALID_JWT is a reasonable default for JWT-based auth failures triggering this entry point.
    String errorMessage = ApiErrorMessages.INVALID_JWT; // Default message for 401

    // You could potentially inspect authException type for more specific messages,
    // but often specific exceptions like BadCredentialsException are caught later
    // by the AuthenticationManager and might not trigger the *entry point* directly
    // if initial token processing fails.
    // Example (less common for entry point):
    // if (authException instanceof InsufficientAuthenticationException) {
    //     errorMessage = "Full authentication is required to access this resource.";
    // }

    // Create the standard ApiError response for 401 Unauthorized
    ApiError apiError = new ApiError(
            HttpStatus.UNAUTHORIZED,
            errorMessage,
            requestUri
    );

    // Set response status and content type
    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED); // 401 Unauthorized
    response.setContentType(MediaType.APPLICATION_JSON_VALUE); // Content-Type: application/json

    // Write the ApiError JSON to the response output stream
    try (OutputStream out = response.getOutputStream()) {
      objectMapper.writeValue(out, apiError);
      log.debug("Sent 401 Unauthorized ApiError response for path '{}'", requestUri);
    } catch (IOException e) {
      log.error("Error writing 401 Unauthorized response to output stream for path '{}'", requestUri, e);
      // Re-throw IO exception as we cannot recover here
      throw e;
    }
  }
}