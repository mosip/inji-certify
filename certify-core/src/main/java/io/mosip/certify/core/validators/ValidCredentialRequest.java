package io.mosip.certify.core.validators;

import io.mosip.certify.core.constants.ErrorConstants;

import javax.validation.Constraint;
import javax.validation.Payload;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Constraint(validatedBy = CredentialRequestValidator.class)
@Target({ElementType.TYPE, ElementType.ANNOTATION_TYPE, ElementType.METHOD, ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
public @interface ValidCredentialRequest {

    String message() default ErrorConstants.INVALID_REQUEST;
    @interface List {
        ValidCredentialRequest[] value();
    }
    Class <?> [] groups() default {};
    Class <? extends Payload> [] payload() default {};

}
