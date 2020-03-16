package com.sap.bulletinboard.ads.config;

import static org.springframework.http.HttpMethod.*;

import com.sap.cloud.security.adapter.spring.SAPOfflineTokenServicesCloud;
import com.sap.cloud.security.config.Environments;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.web.client.RestTemplate;

@Configuration
@EnableWebSecurity
@PropertySource(factory = XsuaaServicePropertySourceFactory.class, value = { "" })
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    public static final String DISPLAY_SCOPE_LOCAL = "Display";
    public static final String UPDATE_SCOPE_LOCAL = "Update";

    @Autowired
    XsuaaServiceConfigurationDefault xsuaaServiceConfiguration;

    // configure Spring Security, demand authentication and specific scopes
    @Override
    public void configure(HttpSecurity http) throws Exception {

        // @formatter:off
        http
            .sessionManagement()
                // session is created by approuter
                .sessionCreationPolicy(SessionCreationPolicy.NEVER)
                .and()
                    // demand specific scopes depending on intended request
                    .authorizeRequests()
                    .antMatchers(GET, "/health", "/").permitAll() //used as health check on CF: must be accessible by "anybody"
                    .antMatchers(POST, "/api/v1/ads/**").hasAuthority(UPDATE_SCOPE_LOCAL)
                    .antMatchers(PUT, "/api/v1/ads/**").hasAuthority(UPDATE_SCOPE_LOCAL)
                    .antMatchers(DELETE, "/api/v1/ads/**").hasAuthority(UPDATE_SCOPE_LOCAL)
                    .antMatchers(GET, "/api/v1/ads/**").hasAuthority(DISPLAY_SCOPE_LOCAL)
                    .anyRequest().denyAll() // deny anything not configured above
                .and()
                    .oauth2ResourceServer()
                    .jwt()
                    .jwtAuthenticationConverter(getJwtAuthenticationConverter());
        // @formatter:on
    }

    @Bean
    JwtDecoder jwtDecoder() {
        return new XsuaaJwtDecoderBuilder(xsuaaServiceConfiguration).build();
    }

    /**
     * Customizes how GrantedAuthority are derived from a Jwt
     */
    Converter<Jwt, AbstractAuthenticationToken> getJwtAuthenticationConverter() {
        TokenAuthenticationConverter converter = new TokenAuthenticationConverter(xsuaaServiceConfiguration);
        converter.setLocalScopeAsAuthorities(true);
        return converter;
    }

}