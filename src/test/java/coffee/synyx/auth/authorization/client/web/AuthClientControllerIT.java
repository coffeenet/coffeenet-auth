package coffee.synyx.auth.authorization.client.web;

import org.junit.Before;
import org.junit.Test;

import org.junit.runner.RunWith;

import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;

import org.springframework.security.oauth2.provider.ClientAlreadyExistsException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.security.test.context.support.WithMockUser;

import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import org.springframework.validation.BindingResult;

import org.springframework.web.context.WebApplicationContext;

import java.util.ArrayList;

import javax.servlet.Filter;

import static org.hamcrest.CoreMatchers.is;

import static org.hamcrest.Matchers.hasProperty;

import static org.mockito.Matchers.any;

import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;


/**
 * @author  Yannic Klem - klem@synyx.de
 */
@RunWith(SpringRunner.class)
@SpringBootTest
public class AuthClientControllerIT {

    @Autowired
    private WebApplicationContext webContext;

    @Autowired
    private Filter springSecurityFilterChain;

    @MockBean
    private JdbcClientDetailsService jdbcClientDetailsServiceMock;

    private MockMvc mockMvc;

    @Before
    public void setupMockMvc() {

        mockMvc = MockMvcBuilders.webAppContextSetup(webContext).apply(springSecurity(springSecurityFilterChain))
            .build();
    }


    @Test
    public void getAllClientsViewRedirectsToLoginIfNotLoggedIn() throws Exception {

        ResultActions resultActions = mockMvc.perform(get("/clients"));
        resultActions.andExpect(status().is3xxRedirection());
        resultActions.andExpect(redirectedUrl("http://localhost/login"));
    }


    @Test
    @WithMockUser
    public void getAllClientsViewShowClientsViewIfLoggedIn() throws Exception {

        when(jdbcClientDetailsServiceMock.listClientDetails()).thenReturn(new ArrayList<>());

        ResultActions resultActions = mockMvc.perform(get("/clients"));
        resultActions.andExpect(status().isOk());
        resultActions.andExpect(view().name("oauth/clients/all"));
        resultActions.andExpect(model().attributeExists("clients"));
        resultActions.andExpect(model().attribute("clients", new ArrayList<>()));
    }


    @Test
    public void getEditViewRedirectsToLoginIfNotLoggedIn() throws Exception {

        ResultActions resultActions = mockMvc.perform(get("/clients/myApp/edit"));
        resultActions.andExpect(status().is3xxRedirection());
        resultActions.andExpect(redirectedUrl("http://localhost/login"));
    }


    @Test
    @WithMockUser(roles = { "EMPLOYEE" })
    public void getEditViewRedirectsToAccessDeniedViewIfLoggedInAsEmployee() throws Exception {

        when(jdbcClientDetailsServiceMock.loadClientByClientId("myApp")).thenReturn(mock(ClientDetails.class));

        ResultActions resultActions = mockMvc.perform(get("/clients/myApp/edit"));
        resultActions.andExpect(status().is3xxRedirection());
        resultActions.andExpect(redirectedUrl("/forbidden"));
    }


    @Test
    @WithMockUser(roles = { "COFFEENET-ADMIN" })
    public void getEditViewReturnsEditViewIfLoggedInAsCoffeeNetAdmin() throws Exception {

        when(jdbcClientDetailsServiceMock.loadClientByClientId("myApp")).thenReturn(new AuthClient());

        ResultActions resultActions = mockMvc.perform(get("/clients/myApp/edit"));
        resultActions.andExpect(status().isOk());
        resultActions.andExpect(view().name("oauth/clients/edit"));
        resultActions.andExpect(model().attributeExists("client"));
    }


    @Test
    public void getDeleteConfirmationViewRedirectsToLoginIfNotLoggedIn() throws Exception {

        ResultActions resultActions = mockMvc.perform(get("/clients/myApp/delete"));
        resultActions.andExpect(status().is3xxRedirection());
        resultActions.andExpect(redirectedUrl("http://localhost/login"));
    }


    @Test
    @WithMockUser(roles = "EMPLOYEE")
    public void getDeleteConfirmationViewRedirectsToAccessDeniedViewIfLoggedInAsEmployee() throws Exception {

        ResultActions resultActions = mockMvc.perform(get("/clients/myApp/delete"));
        resultActions.andExpect(status().is3xxRedirection());
        resultActions.andExpect(redirectedUrl("/forbidden"));
    }


    @Test
    @WithMockUser(roles = { "COFFEENET-ADMIN" })
    public void getDeleteConfirmationViewReturnsDeleteConfirmationViewIfLoggedInAsCoffeeNetAdmin() throws Exception {

        when(jdbcClientDetailsServiceMock.loadClientByClientId("myApp")).thenReturn(new AuthClient());

        ResultActions resultActions = mockMvc.perform(get("/clients/myApp/delete"));
        resultActions.andExpect(status().isOk());
        resultActions.andExpect(view().name("oauth/clients/confirm_delete"));
        resultActions.andExpect(model().attributeExists("client"));
    }


    @Test
    public void getNewClientViewRedirectsToLoginIfNotLoggedIn() throws Exception {

        ResultActions resultActions = mockMvc.perform(get("/clients/new"));
        resultActions.andExpect(status().is3xxRedirection());
        resultActions.andExpect(redirectedUrl("http://localhost/login"));
    }


    @Test
    @WithMockUser(roles = "EMPLOYEE")
    public void getNewClientViewRedirectsToAccessDeniedViewIfLoggedInAsEmployee() throws Exception {

        ResultActions resultActions = mockMvc.perform(get("/clients/new"));
        resultActions.andExpect(status().is3xxRedirection());
        resultActions.andExpect(redirectedUrl("/forbidden"));
    }


    @Test
    @WithMockUser(roles = { "COFFEENET-ADMIN" })
    public void getNewClientViewReturnsNewClientViewIfLoggedInAsCoffeeNetAdmin() throws Exception {

        ResultActions resultActions = mockMvc.perform(get("/clients/new"));
        resultActions.andExpect(status().isOk());
        resultActions.andExpect(view().name("oauth/clients/new"));
        resultActions.andExpect(model().attributeExists("client"));
    }


    @Test
    @WithMockUser(roles = { "COFFEENET-ADMIN" })
    public void getNewClientViewWithDefaultValues() throws Exception {

        ResultActions resultActions = mockMvc.perform(get("/clients/new"));
        resultActions.andExpect(status().isOk());
        resultActions.andExpect(view().name("oauth/clients/new"));
        resultActions.andExpect(model().attributeExists("client"));
        resultActions.andExpect(model().attribute("client", hasProperty("scope", is("openid"))));
        resultActions.andExpect(model().attribute("client",
                hasProperty("authorizedGrantTypes", is("authorization_code,password,client_credentials,refresh_token"))));
        resultActions.andExpect(model().attribute("client", hasProperty("authorities", is(""))));
    }


    @Test
    public void getClientViewRedirectsToLoginIfNotLoggedIn() throws Exception {

        ResultActions resultActions = mockMvc.perform(get("/clients/myApp"));
        resultActions.andExpect(status().is3xxRedirection());
        resultActions.andExpect(redirectedUrl("http://localhost/login"));
    }


    @Test
    @WithMockUser
    public void getClientViewReturnsNewClientViewIfLoggedIn() throws Exception {

        when(jdbcClientDetailsServiceMock.loadClientByClientId("myApp")).thenReturn(new AuthClient());

        ResultActions resultActions = mockMvc.perform(get("/clients/myApp"));
        resultActions.andExpect(status().isOk());
        resultActions.andExpect(view().name("oauth/clients/specific"));
        resultActions.andExpect(model().attributeExists("client"));
    }


    @Test
    public void updateClientRedirectsToLoginIfNotLoggedIn() throws Exception {

        ResultActions resultActions = mockMvc.perform(put("/clients/myApp").with(csrf())
                .param("clientId", "myApp")
                .param("clientSecret", "myAppSecret")
                .param("registeredRedirectUri", "https://coffeenet"));

        resultActions.andExpect(status().is3xxRedirection());
        resultActions.andExpect(redirectedUrl("http://localhost/login"));
    }


    @Test
    @WithMockUser(roles = "EMPLOYEE")
    public void updateClientRedirectsToForbiddenIfLoggedInAsEmployee() throws Exception {

        ResultActions resultActions = mockMvc.perform(put("/clients/myApp").with(csrf())
                .param("clientId", "myApp")
                .param("clientSecret", "myAppSecret")
                .param("registeredRedirectUri", "https://coffeenet"));

        resultActions.andExpect(status().is3xxRedirection());
        resultActions.andExpect(redirectedUrl("/forbidden"));
    }


    @Test
    @WithMockUser(roles = "COFFEENET-ADMIN")
    public void updateClientReturnsBindingErrorsIfLoggedInAsCoffeeNetAdminAndClientDetailsAreInvalid()
        throws Exception {

        ResultActions resultActions = mockMvc.perform(put("/clients/myApp").with(csrf())
                .param("clientId", "myApp")
                .param("clientSecret", "myAppSecret")
                .param("registeredRedirectUri", "https://.coffeenet"));

        resultActions.andExpect(status().isOk());
        resultActions.andExpect(view().name("oauth/clients/edit"));
        resultActions.andExpect(model().attributeExists(BindingResult.MODEL_KEY_PREFIX + "client"));
        resultActions.andExpect(model().attributeHasFieldErrorCode("client", "registeredRedirectUri",
                "error.validation.clientdetails.uri"));

        verify(jdbcClientDetailsServiceMock, never()).updateClientDetails(any(ClientDetails.class));
        verify(jdbcClientDetailsServiceMock, never()).updateClientSecret("myApp", "myAppSecret");
    }


    @Test
    @WithMockUser(roles = "COFFEENET-ADMIN")
    public void updateClientUpdatesClientIfLoggedInAsCoffeeNetAdminAndClientDetailsAreValid() throws Exception {

        ResultActions resultActions = mockMvc.perform(put("/clients/myApp").with(csrf())
                .param("clientId", "myApp")
                .param("clientSecret", "myAppSecret")
                .param("registeredRedirectUri", "https://coffeenet"));

        resultActions.andExpect(status().is3xxRedirection());
        resultActions.andExpect(redirectedUrl("/clients"));

        verify(jdbcClientDetailsServiceMock).updateClientDetails(any(ClientDetails.class));
        verify(jdbcClientDetailsServiceMock).updateClientSecret("myApp", "myAppSecret");
    }


    @Test
    public void createNewClientRedirectsToLoginIfNotLoggedIn() throws Exception {

        ResultActions resultActions = mockMvc.perform(post("/clients").with(csrf())
                .param("clientId", "myApp")
                .param("clientSecret", "myAppSecret")
                .param("registeredRedirectUri", "https://coffeenet"));

        resultActions.andExpect(status().is3xxRedirection());
        resultActions.andExpect(redirectedUrl("http://localhost/login"));
    }


    @Test
    @WithMockUser(roles = "EMPLOYEE")
    public void createNewClientRedirectsToForbiddenIfLoggedInAsEmployee() throws Exception {

        ResultActions resultActions = mockMvc.perform(post("/clients").with(csrf())
                .param("clientId", "myApp")
                .param("clientSecret", "myAppSecret")
                .param("registeredRedirectUri", "https://coffeenet"));

        resultActions.andExpect(status().is3xxRedirection());
        resultActions.andExpect(redirectedUrl("/forbidden"));
    }


    @Test
    @WithMockUser(roles = "COFFEENET-ADMIN")
    public void createNewClientReturnsBindingErrorsIfLoggedInAsCoffeeNetAdminAndClientDetailsAreInvalid()
        throws Exception {

        ResultActions resultActions = mockMvc.perform(post("/clients").with(csrf())
                .param("clientId", "myApp")
                .param("clientSecret", "myAppSecret")
                .param("registeredRedirectUri", "https://.coffeenet"));

        resultActions.andExpect(status().isOk());
        resultActions.andExpect(view().name("oauth/clients/new"));
        resultActions.andExpect(model().attributeExists(BindingResult.MODEL_KEY_PREFIX + "client"));
        resultActions.andExpect(model().attributeHasFieldErrors("client", "registeredRedirectUri"));
        resultActions.andExpect(model().attributeHasFieldErrorCode("client", "registeredRedirectUri",
                "error.validation.clientdetails.uri"));

        verify(jdbcClientDetailsServiceMock, never()).addClientDetails(any(ClientDetails.class));
    }


    @Test
    @WithMockUser(roles = "COFFEENET-ADMIN")
    public void createNewClientReturnsBindingErrorsIfLoggedInAsCoffeeNetAdminAndClientIdAlreadyExists()
        throws Exception {

        doThrow(new ClientAlreadyExistsException("myApp already exists")).when(jdbcClientDetailsServiceMock)
            .addClientDetails(any(ClientDetails.class));

        ResultActions resultActions = mockMvc.perform(post("/clients").with(csrf())
                .param("clientId", "myApp")
                .param("clientSecret", "myAppSecret")
                .param("registeredRedirectUri", "https://coffeenet"));

        resultActions.andExpect(status().isOk());
        resultActions.andExpect(view().name("oauth/clients/new"));
        resultActions.andExpect(model().attributeExists(BindingResult.MODEL_KEY_PREFIX + "client"));
        resultActions.andExpect(model().attributeHasFieldErrors("client", "clientId"));
        resultActions.andExpect(model().attributeHasFieldErrorCode("client", "clientId",
                "error.client.creation.id.alreadyexists"));

        verify(jdbcClientDetailsServiceMock).addClientDetails(any(ClientDetails.class));
    }


    @Test
    @WithMockUser(roles = "COFFEENET-ADMIN")
    public void createNewClientCreatesClientAndRedirectsToClientsIfLoggedInAsCoffeeNetAdmin() throws Exception {

        ResultActions resultActions = mockMvc.perform(post("/clients").with(csrf())
                .param("clientId", "myApp")
                .param("clientSecret", "myAppSecret")
                .param("registeredRedirectUri", "https://coffeenet"));

        resultActions.andExpect(status().is3xxRedirection());
        resultActions.andExpect(redirectedUrl("/clients"));

        verify(jdbcClientDetailsServiceMock).addClientDetails(any(ClientDetails.class));
    }


    @Test
    public void deleteClientRedirectsToLoginIfNotLoggedIn() throws Exception {

        ResultActions resultActions = mockMvc.perform(delete("/clients/myApp").with(csrf()));
        resultActions.andExpect(status().is3xxRedirection());
        resultActions.andExpect(redirectedUrl("http://localhost/login"));
    }


    @Test
    @WithMockUser(roles = "EMPLOYEE")
    public void deleteClientRedirectsToAccessDeniedViewIfLoggedInAsEmployee() throws Exception {

        ResultActions resultActions = mockMvc.perform(delete("/clients/myApp").with(csrf()));
        resultActions.andExpect(status().is3xxRedirection());
        resultActions.andExpect(redirectedUrl("/forbidden"));
    }


    @Test
    @WithMockUser(roles = { "COFFEENET-ADMIN" })
    public void deleteClientDeletesClientAndReturnsClientsViewIfLoggedInAsCoffeeNetAdmin() throws Exception {

        ResultActions resultActions = mockMvc.perform(delete("/clients/myApp").with(csrf()));
        resultActions.andExpect(status().is3xxRedirection());
        resultActions.andExpect(redirectedUrl("/clients"));

        verify(jdbcClientDetailsServiceMock).removeClientDetails("myApp");
    }
}
