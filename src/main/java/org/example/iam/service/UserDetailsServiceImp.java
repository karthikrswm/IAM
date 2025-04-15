// File: src/main/java/org/example/iam/service/UserDetailsServiceImp.java
package org.example.iam.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.iam.constant.ApiErrorMessages; // For error messages
import org.example.iam.entity.User; // The entity implementing UserDetails
import org.example.iam.repository.UserRepository;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional; // Required for lazy loading within the method scope

import java.util.stream.Collectors;

/**
 * Implementation of Spring Security's {@link UserDetailsService} interface.
 * <p>
 * This service is responsible for loading user-specific data (including username, password,
 * authorities/roles, and account status flags) based on a username or primary email address
 * provided during the authentication process.
 * </p>
 * <p>
 * It fetches the custom {@link User} entity, which itself implements {@link UserDetails},
 * ensuring all necessary information is available for Spring Security's authentication providers
 * (like {@code DaoAuthenticationProvider}) to validate credentials and establish the security context.
 * </p>
 * <p>
 * The {@code @Transactional(readOnly = true)} annotation is crucial here to ensure that any
 * lazily-loaded associations within the {@code User} entity (like roles or the organization)
 * can be accessed by Spring Security components after this method returns but within the same
 * transaction boundary managed by the framework during authentication.
 * </p>
 */
@Service("userDetailsService") // Explicit bean name, referenced in SecurityConfig
@RequiredArgsConstructor
@Slf4j
public class UserDetailsServiceImp implements UserDetailsService {

    private final UserRepository userRepository;

    /**
     * Locates the user based on the username or primary email.
     * <p>
     * This method is invoked by Spring Security's authentication mechanism. It attempts to find
     * a user first by matching the provided {@code usernameOrEmail} against the username field
     * (case-insensitive) and, if not found, then against the primary email field (case-insensitive).
     * </p>
     *
     * @param usernameOrEmail The username or primary email identifying the user whose data is required.
     * @return A fully populated {@link UserDetails} object (our {@link User} entity).
     * @throws UsernameNotFoundException if a user with the given username or email could not be found.
     */
    @Override
    @Transactional(readOnly = true) // Ensures lazy-loaded associations (e.g., roles) can be accessed by Spring Security later
    public UserDetails loadUserByUsername(String usernameOrEmail) throws UsernameNotFoundException {
        log.debug("Attempting to load UserDetails for username/email: '{}'", usernameOrEmail);

        // Attempt to find user by username (ignore case), then fallback to primary email (ignore case)
        User user = userRepository.findByUsernameIgnoreCase(usernameOrEmail)
                .or(() -> {
                    log.trace("Username '{}' not found, attempting lookup by primary email.", usernameOrEmail);
                    return userRepository.findByPrimaryEmailIgnoreCase(usernameOrEmail);
                })
                .orElseThrow(() -> {
                    // User not found by either username or email
                    String errorMessage = String.format(ApiErrorMessages.USER_NOT_FOUND_USERNAME, usernameOrEmail);
                    log.warn(errorMessage);
                    return new UsernameNotFoundException(errorMessage); // Throw standard Spring Security exception
                });

        // User found, log details (avoid logging sensitive info like password hash in production INFO/WARN)
        // Note: Accessing user.getAuthorities() here triggers the EAGER fetch of roles or lazy loading within the transaction.
        log.debug("UserDetails found for: ID='{}', Username='{}', PrimaryEmail='{}', OrgID='{}', Roles={}, Enabled={}, Locked={}, CredsExpired={}",
                user.getId(),
                user.getUsername(),
                user.getPrimaryEmail(),
                (user.getOrganization() != null) ? user.getOrganization().getId() : "N/A", // Safely access Org ID
                user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.joining(",")), // Log role names
                user.isEnabled(),
                !user.isAccountNonLocked(),
                !user.isCredentialsNonExpired()
        );

        // Return the User entity itself, as it implements UserDetails.
        // Spring Security will subsequently call methods like getPassword(), isEnabled(), getAuthorities(), etc. on this object.
        return user;
    }
}