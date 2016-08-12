package de.alpharogroup.auth.models;

import java.util.Set;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

/**
 * The Class AuthenticationResult holds the user object and a set of
 * authentication errors if occurred.
 *
 * @param <U>
 *            the generic type of the user object
 * @param <E>
 *            the element type of the authentication errors
 */

@Getter
@Setter
@EqualsAndHashCode
@ToString
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuthenticationResult<U, E> {

	/** The authentication errors. */
	private Set<E> validationErrors;

	/** The user object. */
	private U user;

}