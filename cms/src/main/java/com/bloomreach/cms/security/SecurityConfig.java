package com.bloomreach.cms.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.springframework.security.config.Customizer.*;

@EnableWebSecurity
@Configuration
@PropertySource("classpath:application.properties")
public class SecurityConfig {
    private static final Logger log = LoggerFactory.getLogger(SecurityConfig.class);
    @Value("${saml.metadata.url}")
    String metadataUrl;

    @Bean
    SecurityFilterChain configure(HttpSecurity http) throws Exception {

        final OpenSaml4AuthenticationProvider authenticationProvider = new OpenSaml4AuthenticationProvider();
        authenticationProvider.setResponseAuthenticationConverter(groupsConverter());

        return http.csrf().disable()
                .authorizeHttpRequests()
                .requestMatchers(
                        new AntPathRequestMatcher("/saml2**"),
                        new AntPathRequestMatcher("/login**"),
                        new AntPathRequestMatcher("*.ico"),
                        new AntPathRequestMatcher("*.gif"),
                        new AntPathRequestMatcher("*.jpg"),
                        new AntPathRequestMatcher("*.jpeg"),
                        new AntPathRequestMatcher("*.png"),
                        new AntPathRequestMatcher("*.js"),
                        new AntPathRequestMatcher("*.css")
                ).permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .addFilterAfter(new LoginSuccessFilter(), AuthorizationFilter.class)
                .saml2Login(saml2 -> saml2
                        .authenticationManager(new CmsAuthenticationManager(authenticationProvider))
                )
                .saml2Logout(withDefaults())
                .build();

    }

    @Bean(name = "mvcHandlerMappingIntrospector")
    public HandlerMappingIntrospector mvcHandlerMappingIntrospector() {
        return new HandlerMappingIntrospector();
    }

    @Bean
    public RelyingPartyRegistrationRepository relyingPartyRegistrations() {
        log.info("Using  {}", metadataUrl);
        RelyingPartyRegistration registration = RelyingPartyRegistrations
                .fromMetadataLocation(metadataUrl)
                .registrationId("okta")
                .build();
        return new InMemoryRelyingPartyRegistrationRepository(registration);
    }


    private Converter<OpenSaml4AuthenticationProvider.ResponseToken, Saml2Authentication> groupsConverter() {

        final Converter<OpenSaml4AuthenticationProvider.ResponseToken, Saml2Authentication> delegate =
                OpenSaml4AuthenticationProvider.createDefaultResponseAuthenticationConverter();

        return (responseToken) -> {
            final Saml2Authentication authentication = delegate.convert(responseToken);
            final Saml2AuthenticatedPrincipal principal = (Saml2AuthenticatedPrincipal) authentication.getPrincipal();
            final List<String> groups = principal.getAttribute("groups");
            final Set<GrantedAuthority> authorities = new HashSet<>();
            if (groups != null) {
                groups.stream().map(SimpleGrantedAuthority::new).forEach(authorities::add);
            } else {
                authorities.addAll(authentication.getAuthorities());
            }
            return new Saml2Authentication(principal, authentication.getSaml2Response(), authorities);
        };
    }
}
