// File: src/main/java/org/example/iam/dto/AuditEventDto.java
package com.example.iam.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.time.Instant;
import java.util.UUID;


@Data // Generates getters, setters, toString, equals, hashCode, required args constructor
@Builder // Enables the builder pattern for object creation
@NoArgsConstructor // Generates a no-arguments constructor (needed by Jackson/JPA)
@AllArgsConstructor // Generates an all-arguments constructor
@JsonInclude(JsonInclude.Include.NON_NULL) // Exclude null fields during JSON serialization
public class AuditEventDto {

  private UUID eventId;

  private Instant eventTimestamp;

  private String eventType; // String representation of AuditEventType

  private String actor;

  private String status;

  private String description;

  private String targetResourceType;

  private String targetResourceId; // Use String to accommodate different ID types if needed

  private UUID organizationId; // UUID for org context

  private String details; // Can store JSON details or simple text

}
