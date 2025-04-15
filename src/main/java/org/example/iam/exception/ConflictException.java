// File: src/main/java/org/example/iam/exception/ConflictException.java
package org.example.iam.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Custom runtime exception indicating that a request could not be completed due to a conflict
 * with the current state of the target resource (HTTP 409 Conflict).
 * <p>
 * This is typically used when attempting to create a resource that would violate a uniqueness
 * constraint (e.g., creating a user with an existing username or email, creating an organization
 * with an existing name or domain). It can also be used for updates that would lead to a
 * conflicting state.
 * </p>
 */
@ResponseStatus(HttpStatus.CONFLICT) // Maps to HTTP 409 Conflict
public class ConflictException extends RuntimeException {

  /**
   * Constructs a new ConflictException with the specified detail message.
   *
   * @param message the detail message describing the conflict.
   */
  public ConflictException(String message) {
    super(message);
  }

  /**
   * Constructs a new ConflictException with the specified detail message and cause.
   *
   * @param message the detail message describing the conflict.
   * @param cause   the underlying cause of the exception.
   */
  public ConflictException(String message, Throwable cause) {
    super(message, cause);
  }
}