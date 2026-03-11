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
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException; // <<< ADDED Import
import org.springframework.security.oauth2.core.OAuth2Error; // <<< ADDED Import
//import org.springframework.security.saml2.core.Saml2Exception;
import org.springframework.security.saml2.Saml2Exception;
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
 * Spring Security exceptions (including specific OAuth2/SAML handling), standard Spring
 * MVC/validation exceptions, and provides a catch-all for unexpected errors.
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
  // ... (handleResourceNotFound, handleBadRequest, etc. remain the same) ...
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
    ApiError apiError = new ApiError(HttpStatus.INTERNAL_SERVER_ERROR, ApiErrorMessages.CONFIGURATION_ERROR, path);
    return new ResponseEntity<>(apiError, HttpStatus.INTERNAL_SERVER_ERROR);
  }


  // --- Token Specific Exception Handlers ---
  // ... (handleInvalidToken, handleTokenExpired remain the same) ...
  @ExceptionHandler(InvalidTokenException.class)
  public ResponseEntity<ApiError> handleInvalidToken(InvalidTokenException ex, WebRequest request) {
    String path = getPath(request);
    log.warn("Processing failed due to invalid token at path [{}]: {}", path, ex.getMessage());
    ApiError apiError = new ApiError(HttpStatus.BAD_REQUEST, ex.getMessage(), path);
    return new ResponseEntity<>(apiError, HttpStatus.BAD_REQUEST);
  }

  @ExceptionHandler(TokenExpiredException.class)
  public ResponseEntity<ApiError> handleTokenExpired(TokenExpiredException ex, WebRequest request) {
    String path = getPath(request);
    log.warn("Processing failed due to expired token at path [{}]: {}", path, ex.getMessage());
    ApiError apiError = new ApiError(HttpStatus.GONE, ex.getMessage(), path);
    return new ResponseEntity<>(apiError, HttpStatus.GONE);
  }

  // --- Spring Security Exception Handlers ---

  // Note: AuthenticationException handler covers exceptions from AuthenticationManager/Providers
  @ExceptionHandler({AuthenticationException.class})
  public ResponseEntity<ApiError> handleAuthenticationException(AuthenticationException ex, WebRequest request) {
    // Specific handling for OAuth2AuthenticationException is added below.
    // This handler now acts as a fallback for *other* AuthenticationExceptions.
    String path = getPath(request);
    log.warn("Authentication failure intercepted by GlobalExceptionHandler for path [{}]: {}", path, ex.getMessage());
    HttpStatus status = HttpStatus.UNAUTHORIZED; // Default 401
    String message;
    if (ex instanceof BadCredentialsException) {
      message = ApiErrorMessages.BAD_CREDENTIALS;
    } else if (ex instanceof LockedException) {
      message = ApiErrorMessages.ACCOUNT_LOCKED;
      status = HttpStatus.FORBIDDEN; // 403 better indicates status issue vs just bad creds
    } else if (ex instanceof DisabledException) {
      message = ApiErrorMessages.ACCOUNT_DISABLED;
      status = HttpStatus.FORBIDDEN; // 403 better indicates status issue
    } else if (ex instanceof CredentialsExpiredException) {
      message = ApiErrorMessages.CREDENTIALS_EXPIRED;
    } else if (ex instanceof AuthenticationServiceException) {
      log.error("Authentication service error processing request path [{}]: {}", path, ex.getMessage(), ex.getCause());
      message = ApiErrorMessages.GENERAL_ERROR + " (Authentication Processing Error)";
      status = HttpStatus.INTERNAL_SERVER_ERROR;
    } else {
      message = ApiErrorMessages.AUTHENTICATION_FAILED; // Generic fallback
    }
    ApiError apiError = new ApiError(status, message, path);
    return new ResponseEntity<>(apiError, status);
  }

  // Handles specific OAuth2 Authentication errors
  @ExceptionHandler({OAuth2AuthenticationException.class}) // <<< ADDED Specific Handler
  public ResponseEntity<ApiError> handleOAuth2AuthenticationException(OAuth2AuthenticationException ex, WebRequest request) {
    String path = getPath(request);
    OAuth2Error error = ex.getError();
    String errorCode = error.getErrorCode();
    String errorDescription = error.getDescription(); // Use description from OAuth2Error
    if (errorDescription == null || errorDescription.isBlank()) {
      errorDescription = ex.getMessage(); // Fallback to exception message
    }

    log.warn("OAuth2 Authentication failure for path [{}]: Code='{}', Description='{}'", path, errorCode, errorDescription, ex);

    HttpStatus status = HttpStatus.UNAUTHORIZED; // Default 401 for OAuth2 errors
//     Can map specific OAuth2 error codes to different HTTP statuses if needed
     switch (errorCode) {
         case "invalid_request": status = HttpStatus.BAD_REQUEST; break;
         case "unauthorized_client": status = HttpStatus.UNAUTHORIZED; break;
         case "access_denied": status = HttpStatus.FORBIDDEN; break;
         case "server_error": status = HttpStatus.INTERNAL_SERVER_ERROR; break;
         // Handle custom error codes from CustomOAuth2UserService if needed
         case "user_provisioning_error": status = HttpStatus.INTERNAL_SERVER_ERROR; break; // Or maybe 400?
         case "login_type_mismatch": status = HttpStatus.BAD_REQUEST; break; // Or 403?
         case "organization_not_found": status = HttpStatus.NOT_FOUND; break; // Or 400?
     }

    // Use the description from the OAuth2Error object as the primary message
    ApiError apiError = new ApiError(status, errorDescription, path);
    return new ResponseEntity<>(apiError, status);
  }

  // Handles authorization failures (@PreAuthorize, missing roles etc)
  @ExceptionHandler({AccessDeniedException.class})
  public ResponseEntity<ApiError> handleAccessDenied(AccessDeniedException ex, WebRequest request) {
    String path = getPath(request);
    String user = request.getUserPrincipal() != null ? request.getUserPrincipal().getName() : "anonymous";
    log.warn("Access denied intercepted by GlobalExceptionHandler for user '{}' on path '{}': {}", user, path, ex.getMessage());
    ApiError apiError = new ApiError(HttpStatus.FORBIDDEN, ApiErrorMessages.ACCESS_DENIED, path);
    return new ResponseEntity<>(apiError, HttpStatus.FORBIDDEN);
  }

  // Handler for general SAML2 exceptions that might not be caught elsewhere
  @ExceptionHandler({Saml2Exception.class})
  public ResponseEntity<ApiError> handleSaml2Exception(Saml2Exception ex, WebRequest request) {
    String path = getPath(request);
    log.error("SAML processing error for path [{}]: {}", path, ex.getMessage(), ex);
    ApiError apiError = new ApiError(HttpStatus.INTERNAL_SERVER_ERROR, ApiErrorMessages.GENERAL_ERROR + " (SAML Processing Error)", path);
    return new ResponseEntity<>(apiError, HttpStatus.INTERNAL_SERVER_ERROR);
  }


  // --- Standard Spring Boot Validation/Request Exception Handlers (Overrides from ResponseEntityExceptionHandler) ---
  // ... (handleMethodArgumentNotValid, handleConstraintViolation, etc. remain the same) ...
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

  @ExceptionHandler(ConstraintViolationException.class)
  public ResponseEntity<ApiError> handleConstraintViolation(ConstraintViolationException ex, WebRequest request) {
    Map<String, String> errors = ex.getConstraintViolations().stream()
            .collect(Collectors.toMap(
                    violation -> violation.getPropertyPath().toString(),
                    ConstraintViolation::getMessage
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

  @ExceptionHandler(MethodArgumentTypeMismatchException.class)
  public ResponseEntity<ApiError> handleMethodArgumentTypeMismatch(
          MethodArgumentTypeMismatchException ex, WebRequest request) {
    String requiredType = ex.getRequiredType() != null ? ex.getRequiredType().getSimpleName() : "Unknown";
    String message = String.format("Invalid parameter type for '%s'. Expected '%s'.", ex.getName(), requiredType);
    String path = getPath(request);
    log.warn("Method argument type mismatch for path [{}]: {}", path, message);
    ApiError apiError = new ApiError(HttpStatus.BAD_REQUEST, message, path);
    return new ResponseEntity<>(apiError, HttpStatus.BAD_REQUEST);
  }

  @Override
  protected ResponseEntity<Object> handleMissingServletRequestParameter(
          MissingServletRequestParameterException ex, HttpHeaders headers, HttpStatusCode status, WebRequest request) {
    String message = String.format("Required parameter '%s' is missing.", ex.getParameterName());
    String path = getPath(request);
    log.warn("Missing request parameter for path [{}]: {}", path, message);
    ApiError apiError = new ApiError((HttpStatus) status, message, path);
    return new ResponseEntity<>(apiError, headers, status);
  }


  // --- Generic Catch-All Exception Handler ---
  @ExceptionHandler(Exception.class)
  public ResponseEntity<ApiError> handleAllOtherExceptions(Exception ex, WebRequest request) {
    String path = getPath(request);
    log.error("An unexpected error occurred processing request path [{}]: {}", path, ex.getMessage(), ex);
    ApiError apiError = new ApiError(HttpStatus.INTERNAL_SERVER_ERROR, ApiErrorMessages.GENERAL_ERROR, path);
    return new ResponseEntity<>(apiError, HttpStatus.INTERNAL_SERVER_ERROR);
  }


  // --- Helper Method to Extract Request Path ---
  private String getPath(WebRequest request) {
    try {
      if (request instanceof ServletWebRequest servletWebRequest) {
        return servletWebRequest.getRequest().getRequestURI();
      }
    } catch (Exception e) {
      log.error("Error extracting request path from WebRequest", e);
    }
    return "Unknown path";
  }
}