// File: src/main/java/org/example/iam/api/ApiResponse.java
package org.example.iam.api;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.Setter;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;

import java.time.Instant;

/**
 * Represents a standardized successful API response structure.
 * Provides a consistent format for returning data and status information for successful operations.
 * Fields with null values are excluded from the JSON output.
 *
 * @param <T> The type of the data payload included in the response.
 */
@Getter
@Setter
@JsonInclude(JsonInclude.Include.NON_NULL) // Exclude null fields from JSON serialization
@Schema(description = "Standard success response structure containing data and metadata")
public class ApiSuccessResponse<T> {

  @Schema(description = "HTTP status code indicating the outcome", example = "200")
  private int status;

  @Schema(description = "Timestamp when the response was generated (ISO 8601 format in UTC)",
          example = "2025-04-14T13:17:27.123Z")
  private Instant timestamp;

  @Schema(description = "A human-readable message summarizing the result",
          example = "Operation successful")
  private String message;

  @Schema(description = "The actual data payload of the response (type varies by endpoint)")
  private T data;

  /**
   * Constructs a new ApiResponse with status, message, and data.
   * The timestamp is automatically set to the current time.
   *
   * @param statusCode The HttpStatusCode (e.g., HttpStatus.OK).
   * @param message    A descriptive message for the response.
   * @param data       The data payload (can be null).
   */
  public ApiSuccessResponse(HttpStatusCode statusCode, String message, T data) {
    this.status = statusCode.value();
    this.message = message;
    this.data = data;
    this.timestamp = Instant.now();
  }

  /**
   * Constructs a new ApiResponse with status and message (no data payload).
   * The timestamp is automatically set to the current time.
   *
   * @param statusCode The HttpStatusCode (e.g., HttpStatus.OK).
   * @param message    A descriptive message for the response.
   */
  public ApiSuccessResponse(HttpStatusCode statusCode, String message) {
    this(statusCode, message, null);
  }

  // --- Static Factory Methods for Common Success Scenarios ---

  /**
   * Creates a standard OK (200) response with data and a message.
   *
   * @param data    The data payload.
   * @param message The success message.
   * @param <T>     The type of the data payload.
   * @return An ApiResponse instance representing a 200 OK status.
   */
  public static <T> ApiSuccessResponse<T> ok(T data, String message) {
    return new ApiSuccessResponse<>(HttpStatus.OK, message, data);
  }

  /**
   * Creates a standard OK (200) response with only a message.
   *
   * @param message The success message.
   * @param <T>     The type parameter (typically Void or Object).
   * @return An ApiResponse instance representing a 200 OK status.
   */
  public static <T> ApiSuccessResponse<T> ok(String message) {
    return new ApiSuccessResponse<>(HttpStatus.OK, message);
  }

  /**
   * Creates a standard CREATED (201) response with data and a message.
   * Typically used after successfully creating a resource.
   *
   * @param data    The created resource data payload.
   * @param message The success message.
   * @param <T>     The type of the data payload.
   * @return An ApiResponse instance representing a 201 Created status.
   */
  public static <T> ApiSuccessResponse<T> created(T data, String message) {
    return new ApiSuccessResponse<>(HttpStatus.CREATED, message, data);
  }

  /**
   * Creates a standard CREATED (201) response with only a message.
   *
   * @param message The success message.
   * @param <T>     The type parameter (typically Void or Object).
   * @return An ApiResponse instance representing a 201 Created status.
   */
  public static <T> ApiSuccessResponse<T> created(String message) {
    return new ApiSuccessResponse<>(HttpStatus.CREATED, message);
  }

  /**
   * Creates a standard ACCEPTED (202) response with only a message.
   * Used when a request has been accepted for processing, but completion is not yet confirmed.
   *
   * @param message The acceptance message.
   * @param <T>     The type parameter (typically Void or Object).
   * @return An ApiResponse instance representing a 202 Accepted status.
   */
  public static <T> ApiSuccessResponse<T> accepted(String message) {
    return new ApiSuccessResponse<>(HttpStatus.ACCEPTED, message);
  }

  /**
   * Creates a standard NO CONTENT (204) response with only a message.
   * While 204 typically has no body, this structure allows providing a confirmation message
   * if desired, although the response body might still be empty depending on the controller implementation.
   * Often used for successful DELETE operations where no data needs to be returned.
   *
   * @param message The success message (may not be included in the actual HTTP response body for 204).
   * @param <T>     The type parameter (typically Void or Object).
   * @return An ApiResponse instance representing a 204 No Content status.
   */
  public static <T> ApiSuccessResponse<T> noContent(String message) {
    // Note: Controllers returning 204 should ideally return ResponseEntity.noContent().build();
    // This factory method provides the structure if a message *were* to be included conceptually.
    return new ApiSuccessResponse<>(HttpStatus.NO_CONTENT, message);
  }
}