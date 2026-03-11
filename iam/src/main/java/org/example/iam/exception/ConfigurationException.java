// File: src/main/java/org/example/iam/exception/ConfigurationException.java
package org.example.iam.exception;


import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Custom runtime exception indicating an internal server configuration error (HTTP 500 Internal Server Error).
 * <p>
 * Use this exception when a fundamental configuration issue prevents the application
 * from operating correctly. Examples include:
 * <ul>
 * <li>Missing essential application properties.</li>
 * <li>Failure to load critical resources (e.g., required roles from the database).</li>
 * <li>Inconsistent state detected in core configuration entities.</li>
 * <li>Problems initializing essential components due to configuration.</li>
 * </ul>
 * This signals a problem that typically requires operator intervention to fix the
 * application's setup, rather than a transient issue or client error.
 * </p>
 */
@ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR) // Maps to HTTP 500 Internal Server Error
public class ConfigurationException extends RuntimeException {

  /**
   * Constructs a new ConfigurationException with the specified detail message.
   *
   * @param message the detail message explaining the configuration issue.
   */
  public ConfigurationException(String message) {
    super(message);
  }

  /**
   * Constructs a new ConfigurationException with the specified detail message and cause.
   *
   * @param message the detail message explaining the configuration issue.
   * @param cause   the underlying cause of the exception.
   */
  public ConfigurationException(String message, Throwable cause) {
    super(message, cause);
  }
}