package de.synyx.selfservice.auth;

import org.h2.tools.Server;

import org.springframework.beans.factory.annotation.Value;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import org.springframework.context.annotation.Bean;

import java.sql.SQLException;


/**
 * @author  Yannic Klem - klem@synyx.de
 */
@SpringBootApplication // NOSONAR
public class Authserver {

    public static void main(String[] args) { // NOSONAR

        SpringApplication.run(Authserver.class, args);
    }


    @Bean(initMethod = "start", destroyMethod = "stop")
    public Server h2WebServer(@Value("${h2.consolePort}") String h2ConsolePort) throws SQLException {

        return Server.createWebServer("-web", "-webAllowOthers", "-webPort", h2ConsolePort);
    }
}
