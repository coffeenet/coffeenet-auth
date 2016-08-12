package coffee.synyx.auth.config.dev;

import coffee.synyx.auth.oauth.web.AuthClient;

import org.slf4j.Logger;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;

import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;

import javax.annotation.PostConstruct;

import static org.slf4j.LoggerFactory.getLogger;

import static java.lang.invoke.MethodHandles.lookup;


/**
 * @author  Yannic Klem - klem@synyx.de
 */
@Configuration
@DependsOn("liquibase")
@ConfigurationProperties(prefix = "coffeenet")
@ConditionalOnProperty(prefix = "coffeenet", name = "development", havingValue = "true", matchIfMissing = true)
public class DevelopmentConfiguration {

    private static final Logger LOGGER = getLogger(lookup().lookupClass());

    private final JdbcClientDetailsService jdbcClientDetailsService;

    public DevelopmentConfiguration(JdbcClientDetailsService jdbcClientDetailsService) {

        this.jdbcClientDetailsService = jdbcClientDetailsService;
    }

    private boolean development;

    public boolean isDevelopment() {

        return development;
    }


    public void setDevelopment(boolean development) {

        this.development = development;
    }


    @PostConstruct
    void createDefaultClient() {

        LOGGER.info("Adding default OAuth Client: testClient/testClientSecret");

        AuthClient authClient = new AuthClient();
        authClient.setAutoApprove(true);
        authClient.setClientId("testClient");
        authClient.setClientSecret("testClientSecret");
        authClient.getScope().add("openid");
        jdbcClientDetailsService.addClientDetails(authClient);
    }
}
