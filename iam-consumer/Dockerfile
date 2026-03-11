## File: iam-consumer/Dockerfile
## Use Eclipse Temurin JDK 21 slim image
#FROM eclipse-temurin:21-jdk-jammy
#
## Set a working directory
#WORKDIR /app
#
## Copy the executable JAR file built by Maven into the image
## Assumes the JAR is in the 'target' directory and follows Spring Boot naming conventions
#COPY target/iam-consumer-0.0.1-SNAPSHOT.jar app.jar
## Expose port if the application runs a web server (e.g., for actuator health checks)
## EXPOSE 8081 # Optional: Expose if server.port is set and actuator is enabled
#
## Command to run the application
## Use exec form to ensure signals are handled correctly
#ENTRYPOINT ["java", "-Dspring.profiles.active=docker", "-jar", "/app/app.jar"]
#
## Optional: Add user/group for security best practices
## RUN addgroup -S spring && adduser -S spring -G spring
## USER spring:spring

# Stage 1: Build using Azul Zulu 21 + Maven
# We use a standard Maven image and point it to the Azul Zulu 21 distribution
FROM maven:3.9.6-eclipse-temurin-21 AS build
WORKDIR /app

# Copy the pom and source
COPY pom.xml .
COPY src ./src

# Build the JAR, skipping tests for a faster build
RUN mvn clean package -DskipTests

# Stage 2: Runtime using Azul Zulu 21 JRE
# This is the official Azul Zulu image for the runtime environment
FROM azul/zulu-openjdk-alpine:21-jre
WORKDIR /app

# Copy the generated JAR from the build stage
COPY --from=build /app/target/iam-consumer-0.0.1-SNAPSHOT.jar app.jar

ENTRYPOINT ["java", "-jar", "app.jar"]