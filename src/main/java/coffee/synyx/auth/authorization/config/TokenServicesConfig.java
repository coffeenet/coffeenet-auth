package coffee.synyx.auth.authorization.config;

import org.slf4j.Logger;

import org.springframework.boot.context.properties.EnableConfigurationProperties;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfiguration;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;

import static org.slf4j.LoggerFactory.getLogger;

import static java.lang.invoke.MethodHandles.lookup;


/**
 * @author  Tobias Knell - knell@synyx.de
 */
@Configuration
@EnableConfigurationProperties(TokenProperties.class)
public class TokenServicesConfig {

    private static final Logger LOGGER = getLogger(lookup().lookupClass());

    private final TokenStore tokenStore;
    private final TokenProperties tokenProperties;

    public TokenServicesConfig(TokenStore tokenStore, TokenProperties tokenProperties) {

        this.tokenStore = tokenStore;
        this.tokenProperties = tokenProperties;
    }

    /**
     * This tokenService is declared as @{@link Primary}, as the {@link ResourceServerConfiguration} can only handle a
     * single {@link ResourceServerTokenServices}, but if we register a tokenService to
     * {@link AuthorizationServerEndpointsConfigurer}, the configurer still exposes a non-overwritable
     * {@link DefaultTokenServices} as a bean, in addition to the one we added to it, resulting in two different
     * TokenServices in the context.
     */
    @Bean
    @Primary
    DefaultTokenServices tokenServices() {

        final DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
        defaultTokenServices.setTokenStore(tokenStore);
        defaultTokenServices.setSupportRefreshToken(tokenProperties.isSupportRefreshToken());
        defaultTokenServices.setReuseRefreshToken(tokenProperties.isReuseRefreshToken());
        defaultTokenServices.setRefreshTokenValiditySeconds(tokenProperties.getRefreshTokenValiditySeconds());
        defaultTokenServices.setAccessTokenValiditySeconds(tokenProperties.getAccessTokenValiditySeconds());

        LOGGER.info("//> DefaultTokenServices created");

        return defaultTokenServices;
    }
}
