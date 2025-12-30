/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.core.validation;

import io.mosip.certify.core.dto.IarRequest;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import org.springframework.util.StringUtils;

public class IarValidator implements ConstraintValidator<ValidIar, IarRequest> {
	@Override
	public boolean isValid(IarRequest value, ConstraintValidatorContext context) {
		if (value == null) {
			context.disableDefaultConstraintViolation();
			context.buildConstraintViolationWithTemplate("IAR request is required")
				   .addConstraintViolation();
			return false;
		}

		boolean hasAuthSession = StringUtils.hasText(value.getAuth_session());
		boolean hasVp = StringUtils.hasText(value.getOpenid4vp_response());

		boolean hasInitial =
			StringUtils.hasText(value.getResponse_type()) &&
			StringUtils.hasText(value.getCode_challenge()) &&
			StringUtils.hasText(value.getCode_challenge_method());

		// Exactly one of the flows must be present
		boolean isPresentationFlow = hasAuthSession && hasVp;
		boolean isInitialFlow = hasInitial && !hasAuthSession && !hasVp;

		if (isPresentationFlow || isInitialFlow) {
			return true;
		}

		context.disableDefaultConstraintViolation();
		context.buildConstraintViolationWithTemplate(
			"Invalid IAR request: either provide auth_session and openid4vp_response, or the initial authorization parameters"
		).addConstraintViolation();
		return false;
	}
}