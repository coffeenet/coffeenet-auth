package coffee.synyx.auth.authorization.client.web;

import org.apache.commons.validator.routines.UrlValidator;

import org.springframework.util.StringUtils;

import org.springframework.validation.Errors;
import org.springframework.validation.Validator;

import java.util.Set;


/**
 * @author  Yannic Klem - yann.klem@gmail.com
 */
public class AuthClientDtoValidator implements Validator {

    private static final UrlValidator URL_VALIDATOR = new UrlValidator(new String[] { "http", "https" },
            UrlValidator.ALLOW_LOCAL_URLS);

    @Override
    public boolean supports(Class<?> aClass) {

        return AuthClientDto.class.equals(aClass);
    }


    @Override
    public void validate(Object o, Errors errors) {

        AuthClientDto authClientDto = (AuthClientDto) o;

        validateUrls(authClientDto.getRegisteredRedirectUri(), errors);
    }


    private static void validateUrls(String registeredRedirectUri, Errors errors) {

        Set<String> urls = StringUtils.commaDelimitedListToSet(registeredRedirectUri);

        for (String url : urls) {
            if (!URL_VALIDATOR.isValid(url)) {
                errors.rejectValue("registeredRedirectUri", "error.validation.clientdetails.uri");

                return;
            }
        }
    }
}
