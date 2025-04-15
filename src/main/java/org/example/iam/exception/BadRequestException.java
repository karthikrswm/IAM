// File: src/main/java/org/example/iam/exception/BadRequestException.java
package org.example.iam.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Custom runtime exception indicating a client-side error that makes the request invalid (HTTP 400 Bad Request).
 * <p>
 * Use this exception for situations where:
 * <ul>
 * <li>Input validation fails beyond standard bean validation (e.g., business rule checks on input).</li>
 * <li>The request state is inconsistent or logically flawed from the client's perspective.</li>
 * <li>Required parameters are missing in a way not caught by standard framework mechanisms.</li>
 * </ul>
 * This helps differentiate general client errors from more specific issues like resource conflicts (409)
 * or authentication failures (401).
 * </p>
 */
@ResponseStatus(HttpStatus.BAD_REQUEST) // Maps to HTTP 400 Bad Request
public class BadRequestException extends RuntimeException {

  /**
   * Constructs a new BadRequestException with the specified detail message.
   *
   * @param message the detail message.
   */
  public BadRequestException(String message) {
    super(message);
  }

  /**
   * Constructs a new BadRequestException with the specified detail message and cause.
   *
   * @param message the detail message.
   * @param cause   the underlying cause of the exception.
   */
  public BadRequestException(String message, Throwable cause) {
    super(message, cause);
  }
}