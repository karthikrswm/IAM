// File: src/main/java/org/example/iam/exception/TokenExpiredException.java
package org.example.iam.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Custom runtime exception indicating that a provided token (e.g., email verification,
 * password reset, JWT authentication token) has passed its expiration time and is no longer valid.
 * <p>
 * This exception maps to an HTTP {@link HttpStatus#GONE} (410) status code,
 * which is appropriate for resources or tokens that were once valid but are now permanently expired.
 * </p>
 */
@ResponseStatus(HttpStatus.GONE) // Maps to HTTP 410 Gone
public class TokenExpiredException extends RuntimeException {

  /**
   * Constructs a new TokenExpiredException with the specified detail message.
   *
   * @param message the detail message.
   */
  public TokenExpiredException(String message) {
    super(message);
  }

  /**
   * Constructs a new TokenExpiredException with the specified detail message and cause.
   *
   * @param message the detail message.
   * @param cause   the underlying cause of the exception.
   */
  public TokenExpiredException(String message, Throwable cause) {
    super(message, cause);
  }
}