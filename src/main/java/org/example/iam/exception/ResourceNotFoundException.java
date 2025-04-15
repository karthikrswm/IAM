// File: src/main/java/org/example/iam/exception/ResourceNotFoundException.java
package org.example.iam.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Custom runtime exception indicating that a requested resource could not be found
 * (HTTP 404 Not Found).
 * <p>
 * Used typically when trying to retrieve, update, or delete a resource by its identifier
 * (e.g., User ID, Organization ID, Token string) and no matching resource exists in the system.
 * </p>
 */
@ResponseStatus(HttpStatus.NOT_FOUND) // Maps to HTTP 404 Not Found
public class ResourceNotFoundException extends RuntimeException {

  /**
   * Constructs a new ResourceNotFoundException with the specified detail message.
   *
   * @param message the detail message.
   */
  public ResourceNotFoundException(String message) {
    super(message);
  }

  /**
   * Constructs a new ResourceNotFoundException with a formatted message.
   *
   * @param resourceName The name of the resource type (e.g., "User", "Organization").
   * @param fieldName    The name of the field used for lookup (e.g., "ID", "username").
   * @param fieldValue   The value of the field that was not found.
   */
  public ResourceNotFoundException(String resourceName, String fieldName, Object fieldValue) {
    super(String.format("%s not found with %s: '%s'", resourceName, fieldName, fieldValue));
  }

  /**
   * Constructs a new ResourceNotFoundException with the specified detail message and cause.
   *
   * @param message the detail message.
   * @param cause   the underlying cause of the exception.
   */
  public ResourceNotFoundException(String message, Throwable cause) {
    super(message, cause);
  }
}