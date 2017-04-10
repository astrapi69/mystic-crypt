package de.alpharogroup.auth.models;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

/**
 * The Class {@link SignInWithRedirectionModel} captures the data for sign in action with redirection feature.
 *
 * @author Asterios Raptis
 */
@Getter
@Setter
@EqualsAndHashCode
@ToString
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SignInWithRedirectionModel<T> implements UsernameSignInModel
{
	/**
	 * The serialVersionUID.
	 */
	private static final long serialVersionUID = 1L;

	/** The email. */
	private String email;

	/** The password. */
	private String password;

	/** The redirect page. */
	private Class<? extends T> redirectPage;

	/** The username. */
	private String username;
}