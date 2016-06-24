package coffee.synyx.auth.security.config;

import org.springframework.context.annotation.Configuration;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.provider.authentication.BearerTokenExtractor;
import org.springframework.security.oauth2.provider.authentication.TokenExtractor;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


/**
 * TODO.
 */
@Configuration
public class OAuth2ResourceServerConfig extends ResourceServerConfigurerAdapter {

    private final TokenExtractor tokenExtractor = new BearerTokenExtractor();

    @Override
    public void configure(HttpSecurity http) throws Exception { // NOSONAR

        http.addFilterAfter(new OncePerRequestFilter() {

                @Override
                protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                    FilterChain filterChain) throws ServletException, IOException {

                    // We don't want to allow access to a resource with no token so clear
                    // the security context in case it is actually an OAuth2Authentication
                    if (tokenExtractor.extract(request) == null) {
                        SecurityContextHolder.clearContext();
                    }

                    filterChain.doFilter(request, response);
                }
            }, AbstractPreAuthenticatedProcessingFilter.class);

        http.authorizeRequests().antMatchers("/webjars/**").permitAll().anyRequest().authenticated();
    }
}
