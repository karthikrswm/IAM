// File: src/main/java/org/example/iam/security/DelegatingLogoutSuccessHandler.java
package org.example.iam.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.example.iam.repository.DatabaseRelyingPartyRegistrationRepository; // <<< IMPORT CONCRETE CLASS
import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.web.authentication.logout.OpenSaml4LogoutRequestResolver;
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2RelyingPartyInitiatedLogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@Slf4j
public class DelegatingLogoutSuccessHandler implements LogoutSuccessHandler {

  private final ApiLogoutSuccessHandler apiLogoutSuccessHandler;
  private final Saml2RelyingPartyInitiatedLogoutSuccessHandler saml2LogoutSuccessHandler;

  // <<< UPDATE CONSTRUCTOR: Use the concrete Database repository to break the cycle >>>
  public DelegatingLogoutSuccessHandler(ApiLogoutSuccessHandler apiLogoutSuccessHandler,
      DatabaseRelyingPartyRegistrationRepository databaseRelyingPartyRegistrationRepository) {
    this.apiLogoutSuccessHandler = apiLogoutSuccessHandler;

    // The resolver happily accepts the concrete class because it implements the required interface
    OpenSaml4LogoutRequestResolver logoutRequestResolver =
        new OpenSaml4LogoutRequestResolver(databaseRelyingPartyRegistrationRepository);

    this.saml2LogoutSuccessHandler =
        new Saml2RelyingPartyInitiatedLogoutSuccessHandler(logoutRequestResolver);
  }

  @Override
  public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
    if (authentication instanceof Saml2Authentication) {
      log.info("[Logout Handler] SAML Authentication detected. Triggering SP-Initiated SLO redirect to IdP.");
      saml2LogoutSuccessHandler.onLogoutSuccess(request, response, authentication);
    } else {
      log.info("[Logout Handler] Standard/JWT Authentication detected. Returning JSON API response.");
      apiLogoutSuccessHandler.onLogoutSuccess(request, response, authentication);
    }
  }
}