/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.core.validation;

import io.mosip.certify.core.dto.UnifiedIarRequest;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class UnifiedIarValidator implements ConstraintValidator<ValidUnifiedIar, UnifiedIarRequest> {
	@Override
	public boolean isValid(UnifiedIarRequest value, ConstraintValidatorContext context) {
		if (value == null) {
			return true;
		}

		boolean hasAuthSession = hasText(value.getAuthSession());
		boolean hasVp = hasText(value.getOpenid4vpPresentation());

		boolean hasInitial =
			hasText(value.getResponseType()) &&
			hasText(value.getCodeChallenge()) &&
			hasText(value.getCodeChallengeMethod()) &&
			hasText(value.getRedirectUri());

		// Exactly one of the flows must be present
		boolean isPresentationFlow = hasAuthSession && hasVp;
		boolean isInitialFlow = hasInitial && !hasAuthSession && !hasVp;

		if (isPresentationFlow || isInitialFlow) {
			return true;
		}

		context.disableDefaultConstraintViolation();
		context.buildConstraintViolationWithTemplate(
			"Invalid IAR request: either provide auth_session and openid4vp_presentation, or the initial authorization parameters"
		).addConstraintViolation();
		return false;
	}

	private boolean hasText(String s) {
		return s != null && !s.trim().isEmpty();
	}
}


