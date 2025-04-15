// File: src/main/java/org/example/iam/exception/InvalidTokenException.java
package org.example.iam.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Custom runtime exception indicating that a provided token (e.g., email verification,
 * password reset, JWT) is invalid for reasons other than expiration.
 * <p>
 * This could be due to:
 * <ul>
 * <li>The token string itself not being found.</li>
 * <li>The token being malformed or having an invalid signature (for JWTs).</li>
 * <li>The token being used for the wrong purpose (e.g., using a password reset token for email verification).</li>
 * </ul>
 * Maps to HTTP {@link HttpStatus#BAD_REQUEST} (400) as the client provided an invalid token.
 * Distinguishes from {@link TokenExpiredException} (410 Gone).
 * </p>
 */
@ResponseStatus(HttpStatus.BAD_REQUEST) // Maps to HTTP 400 Bad Request
public class InvalidTokenException extends RuntimeException {

  /**
   * Constructs a new InvalidTokenException with the specified detail message.
   *
   * @param message the detail message explaining why the token is invalid.
   */
  public InvalidTokenException(String message) {
    super(message);
  }

  /**
   * Constructs a new InvalidTokenException with the specified detail message and cause.
   *
   * @param message the detail message explaining why the token is invalid.
   * @param cause   the underlying cause of the exception (e.g., a JWT parsing exception).
   */
  public InvalidTokenException(String message, Throwable cause) {
    super(message, cause);
  }
}