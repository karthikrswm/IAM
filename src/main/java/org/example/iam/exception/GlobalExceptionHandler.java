// File: src/main/java/org/example/iam/exception/GlobalExceptionHandler.java
package org.example.iam.exception;

import jakarta.servlet.http.HttpServletRequest; // To get request path
import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.iam.api.ApiError; // Standard error response DTO
import org.example.iam.constant.ApiErrorMessages; // Standard error messages
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.ServletWebRequest; // To get request path
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Centralized exception handler for the entire application using {@link RestControllerAdvice}.
 * <p>
 * Intercepts exceptions thrown from controllers or filters (if delegated) and maps them
 * to a standardized {@link ApiError} JSON response. It handles custom application exceptions,
 * Spring Security exceptions, standard Spring MVC/validation exceptions, and provides a
 * catch-all for unexpected errors.
 * </p>
 * <p>
 * Extends {@link ResponseEntityExceptionHandler} to leverage its built-in handling for common
 * Spring web exceptions, which can then be customized. The {@link Order} annotation ensures
 * this handler takes precedence over default Spring Boot error handlers.
 * </p>
 */
@Order(Ordered.HIGHEST_PRECEDENCE) // Ensure this handler is prioritized
@RestControllerAdvice // Makes this component handle exceptions globally for @RestController classes
@Slf4j
@RequiredArgsConstructor // If ObjectMapper or other beans need injection
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {

  // private final ObjectMapper objectMapper; // Inject if needed for custom serialization

  // --- Custom Application Exception Handlers ---

  @ExceptionHandler(ResourceNotFoundException.class)
  public ResponseEntity<ApiError> handleResourceNotFound(ResourceNotFoundException ex, WebRequest request) {
    String path = getPath(request);
    log.warn("Resource not found at path [{}]: {}", path, ex.getMessage());
    ApiError apiError = new ApiError(HttpStatus.NOT_FOUND, ex.getMessage(), path);
    return new ResponseEntity<>(apiError, HttpStatus.NOT_FOUND);
  }

  @ExceptionHandler(BadRequestException.class)
  public ResponseEntity<ApiError> handleBadRequest(BadRequestException ex, WebRequest request) {
    String path = getPath(request);
    log.warn("Bad request for path [{}]: {}", path, ex.getMessage());
    ApiError apiError = new ApiError(HttpStatus.BAD_REQUEST, ex.getMessage(), path);
    return new ResponseEntity<>(apiError, HttpStatus.BAD_REQUEST);
  }

  @ExceptionHandler(ConflictException.class)
  public ResponseEntity<ApiError> handleConflict(ConflictException ex, WebRequest request) {
    String path = getPath(request);
    log.warn("Conflict detected for path [{}]: {}", path, ex.getMessage());
    ApiError apiError = new ApiError(HttpStatus.CONFLICT, ex.getMessage(), path);
    return new ResponseEntity<>(apiError, HttpStatus.CONFLICT);
  }

  @ExceptionHandler(OperationNotAllowedException.class)
  public ResponseEntity<ApiError> handleOperationNotAllowed(OperationNotAllowedException ex, WebRequest request) {
    String path = getPath(request);
    String user = request.getUserPrincipal() != null ? request.getUserPrincipal().getName() : "<unknown>";
    log.warn("Operation not allowed for user '{}' on path [{}]: {}", user, path, ex.getMessage());
    ApiError apiError = new ApiError(HttpStatus.FORBIDDEN, ex.getMessage(), path);
    return new ResponseEntity<>(apiError, HttpStatus.FORBIDDEN);
  }

  @ExceptionHandler(ConfigurationException.class)
  public ResponseEntity<ApiError> handleConfigurationError(ConfigurationException ex, WebRequest request) {
    String path = getPath(request);
    log.error("Internal configuration error affecting path [{}]: {}", path, ex.getMessage(), ex);
    // Return a generic message to the client for internal config errors
    ApiError apiError = new ApiError(HttpStatus.INTERNAL_SERVER_ERROR, ApiErrorMessages.CONFIGURATION_ERROR, path);
    return new ResponseEntity<>(apiError, HttpStatus.INTERNAL_SERVER_ERROR);
  }

  // --- Token Specific Exception Handlers ---

  @ExceptionHandler(InvalidTokenException.class)
  public ResponseEntity<ApiError> handleInvalidToken(InvalidTokenException ex, WebRequest request) {
    String path = getPath(request);
    // Specific logging for invalid tokens might have occurred closer to validation point (e.g., JwtUtils or AuthService)
    log.warn("Processing failed due to invalid token at path [{}]: {}", path, ex.getMessage());
    // Return 400 Bad Request as the token provided by the client was invalid (format, signature, not found, wrong type)
    ApiError apiError = new ApiError(HttpStatus.BAD_REQUEST, ex.getMessage(), path);
    return new ResponseEntity<>(apiError, HttpStatus.BAD_REQUEST);
  }

  @ExceptionHandler(TokenExpiredException.class)
  public ResponseEntity<ApiError> handleTokenExpired(TokenExpiredException ex, WebRequest request) {
    String path = getPath(request);
    // Specific logging for expired tokens might have occurred closer to validation point
    log.warn("Processing failed due to expired token at path [{}]: {}", path, ex.getMessage());
    // Return 410 Gone as the token *was* valid but is now expired.
    ApiError apiError = new ApiError(HttpStatus.GONE, ex.getMessage(), path);
    return new ResponseEntity<>(apiError, HttpStatus.GONE);
  }

  // --- Spring Security Exception Handlers ---

  // Note: These handlers act as a fallback or catch exceptions potentially thrown outside
  // the standard filter chain security points. The custom JwtAuthenticationEntryPoint and
  // CustomAccessDeniedHandler configured in SecurityConfig will likely handle most
  // 401/403 errors originating directly from the security filters first.

  @ExceptionHandler({AuthenticationException.class})
  public ResponseEntity<ApiError> handleAuthenticationException(AuthenticationException ex, WebRequest request) {
    String path = getPath(request);
    log.warn("Authentication failure intercepted by GlobalExceptionHandler for path [{}]: {}", path, ex.getMessage());
    // Determine more specific message based on exception type
    HttpStatus status = HttpStatus.UNAUTHORIZED; // Default 401
    String message;
    if (ex instanceof BadCredentialsException) {
      message = ApiErrorMessages.BAD_CREDENTIALS;
    } else if (ex instanceof LockedException) {
      message = ApiErrorMessages.ACCOUNT_LOCKED;
      status = HttpStatus.FORBIDDEN; // Or keep 401, depends on desired UX
    } else if (ex instanceof DisabledException) {
      message = ApiErrorMessages.ACCOUNT_DISABLED;
      status = HttpStatus.FORBIDDEN; // Or keep 401
    } else if (ex instanceof CredentialsExpiredException) {
      message = ApiErrorMessages.CREDENTIALS_EXPIRED;
    } else {
      // Generic message for other AuthenticationExceptions (e.g., from custom providers)
      message = ApiErrorMessages.AUTHENTICATION_FAILED;
    }
    ApiError apiError = new ApiError(status, message, path);
    return new ResponseEntity<>(apiError, status);
  }

  @ExceptionHandler({AccessDeniedException.class})
  public ResponseEntity<ApiError> handleAccessDenied(AccessDeniedException ex, WebRequest request) {
    String path = getPath(request);
    String user = request.getUserPrincipal() != null ? request.getUserPrincipal().getName() : "anonymous";
    log.warn("Access denied intercepted by GlobalExceptionHandler for user '{}' on path '{}': {}", user, path, ex.getMessage());
    ApiError apiError = new ApiError(HttpStatus.FORBIDDEN, ApiErrorMessages.ACCESS_DENIED, path);
    return new ResponseEntity<>(apiError, HttpStatus.FORBIDDEN);
  }

  // --- Standard Spring Boot Validation/Request Exception Handlers (Overrides from ResponseEntityExceptionHandler) ---

  @Override
  protected ResponseEntity<Object> handleMethodArgumentNotValid(
          MethodArgumentNotValidException ex, HttpHeaders headers, HttpStatusCode status, WebRequest request) {
    Map<String, String> errors = new HashMap<>();
    ex.getBindingResult().getAllErrors().forEach(error -> {
      String fieldName = (error instanceof FieldError fieldError) ? fieldError.getField() : error.getObjectName();
      String errorMessage = error.getDefaultMessage();
      errors.put(fieldName, errorMessage);
    });
    String path = getPath(request);
    log.warn("Validation failed (MethodArgumentNotValid) for path [{}]: {}", path, errors);
    ApiError apiError = new ApiError((HttpStatus) status, ApiErrorMessages.VALIDATION_FAILED, path, errors);
    return new ResponseEntity<>(apiError, headers, status);
  }

  @ExceptionHandler(ConstraintViolationException.class) // Handles validation on path variables, request params etc.
  public ResponseEntity<ApiError> handleConstraintViolation(ConstraintViolationException ex, WebRequest request) {
    Map<String, String> errors = ex.getConstraintViolations().stream()
            .collect(Collectors.toMap(
                    violation -> violation.getPropertyPath().toString(), // Extracts field name
                    ConstraintViolation::getMessage // Extracts validation message
            ));
    String path = getPath(request);
    log.warn("Constraint violation for path [{}]: {}", path, errors);
    ApiError apiError = new ApiError(HttpStatus.BAD_REQUEST, ApiErrorMessages.VALIDATION_FAILED, path, errors);
    return new ResponseEntity<>(apiError, HttpStatus.BAD_REQUEST);
  }

  @Override
  protected ResponseEntity<Object> handleHttpMessageNotReadable(
          HttpMessageNotReadableException ex, HttpHeaders headers, HttpStatusCode status, WebRequest request) {
    String path = getPath(request);
    log.warn("Malformed JSON request for path [{}]: {}", path, ex.getMessage());
    ApiError apiError = new ApiError((HttpStatus) status, ApiErrorMessages.MALFORMED_JSON, path);
    return new ResponseEntity<>(apiError, headers, status);
  }

  @ExceptionHandler(MethodArgumentTypeMismatchException.class) // Handles wrong type for path variable/request param
  public ResponseEntity<ApiError> handleMethodArgumentTypeMismatch(
          MethodArgumentTypeMismatchException ex, WebRequest request) {
    String requiredType = ex.getRequiredType() != null ? ex.getRequiredType().getSimpleName() : "Unknown";
    String message = String.format("Parameter '%s' should be of type '%s'. Value '%s' is invalid.",
            ex.getName(), requiredType, ex.getValue());
    String path = getPath(request);
    log.warn("Method argument type mismatch for path [{}]: {}", path, message);
    ApiError apiError = new ApiError(HttpStatus.BAD_REQUEST, message, path);
    return new ResponseEntity<>(apiError, HttpStatus.BAD_REQUEST);
  }

  @Override
  protected ResponseEntity<Object> handleMissingServletRequestParameter(
          MissingServletRequestParameterException ex, HttpHeaders headers, HttpStatusCode status, WebRequest request) {
    String message = String.format("Required request parameter '%s' of type '%s' is missing.",
            ex.getParameterName(), ex.getParameterType());
    String path = getPath(request);
    log.warn("Missing request parameter for path [{}]: {}", path, message);
    ApiError apiError = new ApiError((HttpStatus) status, message, path);
    return new ResponseEntity<>(apiError, headers, status);
  }


  // --- Generic Catch-All Exception Handler ---
  // This should be the last handler to catch any exceptions not explicitly handled above.
  @ExceptionHandler(Exception.class)
  public ResponseEntity<ApiError> handleAllOtherExceptions(Exception ex, WebRequest request) {
    String path = getPath(request);
    // Log unexpected errors at ERROR level with stack trace
    log.error("An unexpected error occurred processing request path [{}]: {}", path, ex.getMessage(), ex);
    // Return a generic 500 error response to the client
    ApiError apiError = new ApiError(HttpStatus.INTERNAL_SERVER_ERROR, ApiErrorMessages.GENERAL_ERROR, path);
    return new ResponseEntity<>(apiError, HttpStatus.INTERNAL_SERVER_ERROR);
  }


  // --- Helper Method to Extract Request Path ---
  private String getPath(WebRequest request) {
    try {
      // Try to get the servlet request URI
      if (request instanceof ServletWebRequest servletWebRequest) {
        return servletWebRequest.getRequest().getRequestURI();
      }
    } catch (Exception e) {
      // Log error if path extraction fails, but don't let it fail the handler
      log.error("Error extracting request path from WebRequest", e);
    }
    // Fallback if path cannot be determined
    return "Unknown path";
  }
}