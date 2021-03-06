package coffee.synyx.auth.authentication.config;

import coffee.synyx.auth.AuthConfigurationProperties;
import coffee.synyx.auth.resource.config.ResourceServerConfig;

import org.slf4j.Logger;

import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

import org.springframework.context.annotation.Configuration;

import org.springframework.core.annotation.Order;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import static org.slf4j.LoggerFactory.getLogger;

import static org.springframework.http.HttpMethod.GET;

import static java.lang.invoke.MethodHandles.lookup;


/**
 * This configuration configures a form based login for all paths defined in the first ant matcher. It is required for
 * the "authorization_code" grant type flow.
 *
 * <p>Every path NOT matched by this configuration, will be handled by {@link ResourceServerConfig}</p>
 *
 * @author  Yannic Klem - klem@synyx.de
 */
@Configuration
@Order(SecurityProperties.DEFAULT_FILTER_ORDER - 2)
@EnableConfigurationProperties({ ServerProperties.class, AuthConfigurationProperties.class })
public class AuthenticationConfig extends WebSecurityConfigurerAdapter {

    private static final Logger LOGGER = getLogger(lookup().lookupClass());

    private static final String LOGOUT = "/logout";
    private static final String ADMIN_ROLE = "ROLE_COFFEENET-ADMIN";
    private static final String CLIENTS = "/clients/**";

    private final LogoutSuccessHandler logoutSuccessHandler;
    private final ServerProperties serverProperties;
    private final AuthConfigurationProperties authConfigurationProperties;

    @Autowired
    public AuthenticationConfig(LogoutSuccessHandler logoutSuccessHandler, ServerProperties serverProperties,
        AuthConfigurationProperties authConfigurationProperties) {

        this.logoutSuccessHandler = logoutSuccessHandler;
        this.serverProperties = serverProperties;
        this.authConfigurationProperties = authConfigurationProperties;

        LOGGER.info("//> LoginConfig...");
    }

    @Override
    public void configure(WebSecurity web) throws Exception {

        web.ignoring().mvcMatchers("/webjars/**", "/img/**");
    }


    @Override
    public void configure(HttpSecurity http) throws Exception { // NOSONAR

        //J-
        http.requestMatchers()
                .antMatchers("/", "/login", "/oauth/authorize", "/oauth/confirm_access", LOGOUT,
                        CLIENTS, "/forbidden")
            .and()
                .formLogin()
                    .defaultSuccessUrl(authConfigurationProperties.getDefaultRedirectUrl())
                    .loginPage("/login").permitAll()
            .and()
                .logout()
                    .logoutUrl(LOGOUT)
                    .logoutSuccessHandler(logoutSuccessHandler)
                    .deleteCookies(serverProperties.getSession().getCookie().getName())
                .and()
                    .authorizeRequests().antMatchers(GET, LOGOUT).permitAll()
            .and()
                .authorizeRequests()
                .antMatchers("/clients/new", "/clients/*/edit", "/clients/*/delete").hasAuthority(ADMIN_ROLE)
            .and()
                .authorizeRequests()
                .antMatchers(GET, CLIENTS).authenticated()
                .antMatchers(CLIENTS).hasAuthority(ADMIN_ROLE)
                .anyRequest().authenticated()
            .and()
                .exceptionHandling()
                .accessDeniedHandler(new DefaultAccessDeniedHandler(authConfigurationProperties));
        //J+
        LOGGER.info("//> LoginConfig was configured");
    }
}
