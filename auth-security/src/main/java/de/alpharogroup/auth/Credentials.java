package de.alpharogroup.auth;

import java.io.Serializable;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

/**
 * The class {@link Credentials}.
 */
@Getter
@Setter
@EqualsAndHashCode
@ToString
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Credentials implements Serializable
{
	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = -2162099479676305658L;

	/** The username. */
	private String username;

	/** The password. */
	private String password;

}