package de.alpharogroup.auth.models;

/**
 * The Enum {@link AuthenticationErrors}.
 */
public enum AuthenticationErrors {

	/**
	 * This constant indicates that the given email or username does not exist.
	 */
	EMAIL_OR_USERNAME_DOES_NOT_EXIST,

	/** This constant indicates that the given password is invalid. */
	PASSWORD_INVALID,

	/** This constant indicates that the given user object is not registered. */
	UNREGISTERED
};