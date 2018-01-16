/**
 * The MIT License
 *
 * Copyright (C) 2015 Asterios Raptis
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package de.alpharogroup.auth.usermanagement;

import java.io.Serializable;

import de.alpharogroup.auth.enums.InsertUserState;

/**
 * The interface {@link UserExistenceService}.
 */
public interface UserExistenceService extends Serializable
{

	/**
	 * Checks if a user exists with the given email.
	 * 
	 * @param email
	 *            the email
	 * @return true, if successful
	 */
	boolean existsUserWithEmail(final String email);

	/**
	 * Checks if a user exists with the given email or user name.
	 *
	 * @param emailOrUsername
	 *            the email or user name
	 * @return true, if successful
	 */
	boolean existsUserWithEmailOrUsername(final String emailOrUsername);

	/**
	 * Checks if a user exists with the given email or user name.
	 * 
	 * @param email
	 *            the email
	 * @param username
	 *            the user name
	 * @return the resulted {@link InsertUserState} object.
	 */
	InsertUserState existsUserWithEmailOrUsername(final String email, final String username);

	/**
	 * Checks if a user exists with the given user name.
	 * 
	 * @param username
	 *            the user name
	 * @return true, if successful
	 */
	boolean existsUserWithUsername(final String username);

}
