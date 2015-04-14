package de.synyx.selfservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;

/**
 * Created by klem on 13.04.15.
 */
@SpringBootApplication //NOSONAR
@EnableResourceServer
public class Authserver {

    /**
     * Entrypoint of the Application.
     * @param args Will be passed to SpringApplication.run()
     */
    public static void main(String[] args) {
        SpringApplication.run(Authserver.class, args);
    }
}
