// File: src/main/java/org/example/iam/audit/AuditorAwareImpl.java
package org.example.iam.audit;

import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.AuditorAware;
import org.springframework.lang.NonNull; // Using Spring's NonNull for consistency
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component; // Marks this as a Spring managed bean

import java.util.Optional;

/**
 * Implementation of Spring Data JPA's {@link AuditorAware} interface.
 * <p>
 * This component provides the identifier (typically username) of the currently authenticated
 * principal interacting with the system. This identifier is used by JPA Auditing
 * (via {@link org.springframework.data.jpa.domain.support.AuditingEntityListener})
 * to automatically populate the {@code createdBy} and {@code lastModifiedBy} fields
 * in entities that extend the {@link Auditable} base class.
 * </p>
 * <p>
 * It handles different types of principals found in the {@link SecurityContext} and provides
 * standardized identifiers for system-level actions ({@code SYSTEM_AUDITOR}) and
 * unauthenticated or anonymous access ({@code ANONYMOUS_AUDITOR}).
 * </p>
 */
@Component("auditorAware") // Define bean name, matching @EnableJpaAuditing(auditorAwareRef = "auditorAware")
@Slf4j
public class AuditorAwareImpl implements AuditorAware<String> { // Auditor type is String (username/ID)

    /**
     * Standard identifier for actions performed by the system itself (e.g., schedulers).
     */
    public static final String SYSTEM_AUDITOR = "SYSTEM";

    /**
     * Standard identifier for actions performed when no authenticated user is present
     * in the security context (e.g., public endpoints, pre-authentication).
     */
    public static final String ANONYMOUS_AUDITOR = "ANONYMOUS";

    /**
     * Retrieves the identifier of the current auditor from the Spring Security context.
     * <p>
     * The logic attempts to extract the username from the authenticated {@link Authentication} principal.
     * It handles cases where the principal is a {@link UserDetails} object (common case),
     * a simple {@link String}, or other types. If no authenticated principal is found,
     * it defaults to {@link #ANONYMOUS_AUDITOR}.
     * </p>
     * <p>
     * System processes (like scheduled tasks) that perform audited actions should ensure
     * the security context is appropriately set, potentially using {@code RunAsManager} or
     * manually setting an Authentication object with {@link #SYSTEM_AUDITOR} as the principal
     * before performing the action.
     * </p>
     *
     * @return An {@link Optional} containing the auditor's identifier (String). This will be:
     * <ul>
     * <li>The username from {@link UserDetails#getUsername()} if the principal is UserDetails.</li>
     * <li>The principal string itself, unless it's Spring Security's default "anonymousUser", in which case {@link #ANONYMOUS_AUDITOR} is returned.</li>
     * <li>{@link #SYSTEM_AUDITOR} if explicitly set in the context.</li>
     * <li>{@link #ANONYMOUS_AUDITOR} if no authenticated principal is found or recognised.</li>
     * </ul>
     * Never returns an empty Optional or null itself, as per {@link NonNull} contract.
     */
    @Override
    @NonNull // Guarantees the returned Optional itself is not null.
    public Optional<String> getCurrentAuditor() {
        // Use functional style with Optional chaining for safer handling of potentially null context/auth
        return Optional.ofNullable(SecurityContextHolder.getContext())
                .map(SecurityContext::getAuthentication)
                .filter(Authentication::isAuthenticated) // Ensure authentication is valid
                .map(Authentication::getPrincipal)
                .map(principal -> {
                    // Case 1: Standard UserDetails principal
                    if (principal instanceof UserDetails userDetails) {
                        String username = userDetails.getUsername();
                        log.trace("Auditor determined from UserDetails: {}", username);
                        return username;
                    }
                    // Case 2: Principal is a String (e.g., JWT subject, system/anonymous)
                    else if (principal instanceof String principalString) {
                        // Avoid returning Spring Security's internal "anonymousUser"
                        if ("anonymousUser".equalsIgnoreCase(principalString)) {
                            log.trace("Auditor identified as anonymous user via String principal.");
                            return ANONYMOUS_AUDITOR;
                        }
                        // Assume other strings are valid usernames or specific identifiers (like SYSTEM)
                        log.trace("Auditor determined from String principal: {}", principalString);
                        return principalString;
                    }
                    // Case 3: Fallback for unexpected principal types
                    else {
                        String principalClassName = principal.getClass().getName();
                        log.warn("Unexpected principal type found for auditing: {}. Using toString() as fallback.",
                                principalClassName);
                        // Use toString() as a last resort, might not be ideal.
                        return principal.toString();
                    }
                })
                // If any step above resulted in null/empty Optional (e.g., no context, no auth), default to ANONYMOUS.
                .or(() -> {
                    log.trace("No authenticated principal found in SecurityContext. Defaulting auditor to ANONYMOUS.");
                    return Optional.of(ANONYMOUS_AUDITOR);
                });
    }
}