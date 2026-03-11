// File: src/main/java/org/example/iam/exception/OperationNotAllowedException.java
package org.example.iam.exception;

import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException; // For context
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Custom runtime exception indicating that an operation, while potentially authorized by role,
 * is forbidden based on business logic or the current state of the resource (HTTP 403 Forbidden).
 * <p>
 * Use this exception when an authenticated user attempts an action that is disallowed by
 * application rules, even if their role grants them general permission for such actions. Examples:
 * <ul>
 * <li>Attempting to delete or modify an immutable resource (e.g., the Super Organization).</li>
 * <li>Attempting an action that violates the current state (e.g., trying to verify an already verified email).</li>
 * <li>A user trying to perform an action on themselves when it's disallowed (e.g., deleting own account).</li>
 * <li>An admin trying to perform an action on another admin when policy forbids it.</li>
 * </ul>
 * This differs from Spring Security's {@link AccessDeniedException}, which is typically thrown
 * earlier in the filter chain based on role/permission checks configured via method security
 * or request matchers. This exception is usually thrown from the service layer based on business rules.
 * </p>
 */
@ResponseStatus(HttpStatus.FORBIDDEN) // Maps to HTTP 403 Forbidden
public class OperationNotAllowedException extends RuntimeException {

  /**
   * Constructs a new OperationNotAllowedException with the specified detail message.
   *
   * @param message The detail message explaining why the operation is not allowed.
   */
  public OperationNotAllowedException(String message) {
    super(message);
  }

  /**
   * Constructs a new OperationNotAllowedException with the specified detail message and cause.
   *
   * @param message The detail message explaining why the operation is not allowed.
   * @param cause   The underlying cause of the exception.
   */
  public OperationNotAllowedException(String message, Throwable cause) {
    super(message, cause);
  }
}