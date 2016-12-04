package coffee.synyx.auth.config.integration.security;

import coffee.synyx.auth.config.integration.security.ldap.AuthLdapConfigurationProperties;
import coffee.synyx.auth.config.integration.security.ldap.CoffeeDefaultTlsDirContextAuthenticationStrategy;
import coffee.synyx.auth.oauth.user.service.SynyxUserDetailsContextMapper;

import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.boot.context.properties.EnableConfigurationProperties;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import org.springframework.ldap.core.support.LdapContextSource;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configurers.GlobalAuthenticationConfigurerAdapter;


/**
 * Configures an {@link org.springframework.security.authentication.AuthenticationManager authentication manager} to use
 * ldap based on {@link AuthLdapConfigurationProperties}.
 *
 * @author  Yannic Klem - klem@synyx.de
 */
@Configuration
@EnableConfigurationProperties(AuthLdapConfigurationProperties.class)
public class AuthenticationManagerConfiguration extends GlobalAuthenticationConfigurerAdapter {

    private SynyxUserDetailsContextMapper synyxUserDetailsContextMapper;
    private AuthLdapConfigurationProperties authLdapConfigurationProperties;

    @Autowired
    public AuthenticationManagerConfiguration(SynyxUserDetailsContextMapper synyxUserDetailsContextMapper,
        AuthLdapConfigurationProperties authLdapConfigurationProperties) {

        this.synyxUserDetailsContextMapper = synyxUserDetailsContextMapper;
        this.authLdapConfigurationProperties = authLdapConfigurationProperties;
    }

    @Override
    public void init(AuthenticationManagerBuilder auth) throws Exception {

        auth.ldapAuthentication()
            .userSearchBase(authLdapConfigurationProperties.getUserSearchBase())
            .userSearchFilter(authLdapConfigurationProperties.getUserSearchFilter())
            .groupSearchBase(authLdapConfigurationProperties.getGroupSearchBase())
            .groupSearchFilter(authLdapConfigurationProperties.getGroupSearchFilter())
            .contextSource(contextSource())
            .userDetailsContextMapper(synyxUserDetailsContextMapper);
    }


    @Bean
    public LdapContextSource contextSource() {

        LdapContextSource contextSource = new LdapContextSource();
        contextSource.setUrl(authLdapConfigurationProperties.getUrl());
        contextSource.setBase(authLdapConfigurationProperties.getBase());
        contextSource.setAuthenticationStrategy(new CoffeeDefaultTlsDirContextAuthenticationStrategy());

        return contextSource;
    }
}