package com.bloomreach.cms.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider;

public class CmsAuthenticationManager extends ProviderManager {
    private static final Logger log = LoggerFactory.getLogger(CmsAuthenticationManager.class);

    public CmsAuthenticationManager(final OpenSaml4AuthenticationProvider authenticationProvider) {
        super(authenticationProvider);
    }

    @Override
    public Authentication authenticate(final Authentication auth) throws AuthenticationException {
        final Authentication authentication = super.authenticate(auth);
        log.info("authentication {}", authentication);
        return authentication;
    }
}
