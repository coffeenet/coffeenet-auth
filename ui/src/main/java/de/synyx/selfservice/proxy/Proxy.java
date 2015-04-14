package de.synyx.selfservice.proxy;

import de.synyx.selfservice.UiApplication;
import org.apache.log4j.Logger;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.Principal;

/**
 * Created by klem on 13.04.15.
 */
@RestController
public class Proxy {

    @Autowired
    private RestTemplate restTemplate;

    @RequestMapping("/api/user")
    public Principal getUser(Principal user){
        return user;
    }

    /*
    @RequestMapping(value = "/api/{module}/**")
    public String redirectPost(@RequestBody(required = false) String body, @PathVariable("module") String module,
                               HttpMethod method, HttpServletRequest request, HttpServletResponse response)
                               throws URISyntaxException {
        URI targetUri = new URI("http", null, "localhost", 8090, "/" + module, request.getQueryString(), null);
        ResponseEntity<String> responseEntity =
                restTemplate.exchange(targetUri, method, new HttpEntity<String>(body), String.class);
        return responseEntity.getBody();
    }
    */
}
