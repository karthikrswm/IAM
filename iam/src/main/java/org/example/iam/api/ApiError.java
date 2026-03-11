// File: src/main/java/org/example/iam/api/ApiError.java
package org.example.iam.api;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.*;
import org.springframework.http.HttpStatus;

import java.time.Instant;
import java.util.Map;

/**
 * Represents a standardized error response structure for the API.
 * Provides consistent information about errors encountered during request processing.
 * Fields with null values (like validationErrors) are excluded from the JSON output.
 */
@Data // Includes @Getter, @Setter, @ToString, @EqualsAndHashCode, @RequiredArgsConstructor
@NoArgsConstructor // Needed for JSON deserialization frameworks
@AllArgsConstructor // Generates constructor with all fields
@Builder // Enables builder pattern for easier object creation
@JsonInclude(JsonInclude.Include.NON_NULL) // Exclude null fields from JSON output
@Schema(description = "Standard error response structure detailing an API error")
public class ApiError {

  @Builder.Default // Sets a default value using the builder
  @Schema(description = "Timestamp when the error occurred (ISO 8601 format in UTC)",
          example = "2025-04-14T13:33:48.123Z")
  private Instant timestamp = Instant.now();

  @Schema(description = "HTTP status code corresponding to the error", example = "404")
  private int status;

  @Schema(description = "Short, standard HTTP error phrase matching the status code",
          example = "Not Found")
  private String error; // e.g., "Not Found", "Bad Request", "Forbidden"

  @Schema(description = "Detailed, human-readable error message explaining the specific issue",
          example = "User not found with ID: a1b2c3d4-e5f6-7890-abcd-ef1234567890")
  private String message; // Specific error detail

  @Schema(description = "The API path where the error occurred",
          example = "/api/v1/users/a1b2c3d4-e5f6-7890-abcd-ef1234567890")
  private String path; // Request URI

  @Schema(description = "Optional map containing field-specific validation errors (key: field name, value: error message)",
          example = "{\"username\": \"must not be blank\", \"email\": \"must be a well-formed email address\"}",
          nullable = true)
  private Map<String, String> validationErrors; // Optional field for detailed validation messages

  /**
   * Convenience constructor for creating an ApiError without validation details.
   *
   * @param httpStatus The HTTP status of the error.
   * @param message    The detailed error message.
   * @param path       The request path where the error occurred.
   */
  public ApiError(HttpStatus httpStatus, String message, String path) {
    this.timestamp = Instant.now();
    this.status = httpStatus.value();
    this.error = httpStatus.getReasonPhrase();
    this.message = message;
    this.path = path;
    this.validationErrors = null; // Explicitly null
  }

  /**
   * Convenience constructor for creating an ApiError with validation details.
   *
   * @param httpStatus       The HTTP status of the error (typically BAD_REQUEST).
   * @param message          A general error message (e.g., "Validation failed").
   * @param path             The request path where the error occurred.
   * @param validationErrors A map of field-specific validation errors.
   */
  public ApiError(HttpStatus httpStatus, String message, String path, Map<String, String> validationErrors) {
    this(httpStatus, message, path); // Call the other constructor
    this.validationErrors = validationErrors;
  }
}