// File: src/main/java/org/example/iam/IamApplication.java
package org.example.iam;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Contact;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.info.License;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import io.swagger.v3.oas.annotations.servers.Server;
import lombok.RequiredArgsConstructor; // <<< ADDED import
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.core.env.Environment; // <<< ADDED import
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;

import java.util.Arrays;

/**
 * Main entry point for the IAM Service Spring Boot application.
 * <p>
 * Configures and enables key features:
 * <ul>
 * <li>{@link SpringBootApplication}: Standard Spring Boot auto-configuration, component scanning.</li>
 * <li>{@link EnableJpaAuditing}: Activates JPA auditing features, using the specified "auditorAware" bean.</li>
 * <li>{@link EnableScheduling}: Enables detection and execution of @Scheduled tasks.</li>
 * <li>{@link EnableAsync}: Enables asynchronous method execution (@Async).</li>
 * <li>{@link OpenAPIDefinition}: Provides metadata for the OpenAPI (Swagger) documentation.</li>
 * <li>{@link SecurityScheme}: Defines the JWT Bearer authentication scheme for OpenAPI documentation.</li>
 * </ul>
 * </p>
 */
@SpringBootApplication
@EnableJpaAuditing(auditorAwareRef = "auditorAware") // Reference the AuditorAware bean by name
@EnableScheduling // Enable support for @Scheduled tasks
@EnableAsync // Enable support for @Async methods
@OpenAPIDefinition(
        info = @Info(
                title = "IAM Service API",
                version = "1.0.0",
                description = """
                        API documentation for the Multi-Tenant Identity and Access Management (IAM) Service.
                        Provides endpoints for managing organizations (tenants) and users, handling authentication
                        (JWT, SAML 2.0, OAuth 2.0/OIDC), managing SSO configurations, and related identity operations.
                        """,
                contact = @Contact(
                        name = "IAM Service Support",
                        // Consider externalizing contact info to properties if it changes often
                        email = "support-iam@example.com",
                        url = "https://support.example.com/iam"
                ),
                license = @License(
                        name = "Apache 2.0",
                        url = "https://www.apache.org/licenses/LICENSE-2.0.html"
                )
        ),
        servers = {
                // Define servers where the API is hosted (useful for Swagger UI)
                @Server(url = "http://localhost:8080", description = "Local Development Server"),
                @Server(url = "https://qa-iam.example.com", description = "QA Server"),
                @Server(url = "https://iam.example.com", description = "Production Server")
                // Add other servers as needed
        }
)
@SecurityScheme( // Define the security scheme used by the API (JWT Bearer) for Swagger UI
        name = "bearerAuth", // This name is referenced in @SecurityRequirement annotations on controllers
        type = SecuritySchemeType.HTTP, // Type is HTTP-based authentication
        scheme = "bearer", // The scheme is "bearer"
        bearerFormat = "JWT", // Hint that the bearer token is a JWT
        description = "Enter JWT Bearer token obtained after successful login." // Description for Swagger UI
)
@Slf4j // Add SLF4J logging
@RequiredArgsConstructor // <<< ADDED Lombok annotation for constructor injection
public class IamApplication {

    /**
     * Spring Environment instance, injected via constructor by Lombok @RequiredArgsConstructor.
     * Used to access application properties and active profiles.
     */
    private final Environment environment; // <<< ADDED final field for injection

    /**
     * Main method to run the Spring Boot application.
     *
     * @param args Command line arguments.
     */
    public static void main(String[] args) {
        SpringApplication.run(IamApplication.class, args);
        log.info("<<<< IAM Service Application Started >>>>");
    }

    /**
     * Listens for the ContextRefreshedEvent and logs the active Spring profiles.
     * The Environment is accessed via the injected class field 'this.environment'.
     * Javadoc updated to reflect parameter change.
     *
     * @param event The ContextRefreshedEvent object (the only parameter allowed).
     */
    // Explicitly list event class for clarity
    @EventListener(ContextRefreshedEvent.class)
    public void onApplicationEvent(ContextRefreshedEvent event) { // <<< REMOVED Environment env parameter
        // Use the injected 'environment' field instead of the method parameter
        String activeProfiles = Arrays.toString(this.environment.getActiveProfiles());
        String defaultProfiles = Arrays.toString(this.environment.getDefaultProfiles());
        log.info("Active Spring profiles: {}", activeProfiles.isEmpty() ? defaultProfiles : activeProfiles);
    }

}