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
package de.alpharogroup.auth.api;

import java.io.Serializable;
import java.util.Set;

/**
 * The interface {@link User}.
 *
 * @param <P>
 *            the generic type
 * @param <R>
 *            the generic type
 * @version 1.1
 * @author Asterios Raptis
 */
public interface User<P extends Permission, R extends Role<P>> extends Serializable
{

	/**
	 * Adds the given role to the user.
	 *
	 * @param role
	 *            the role
	 */
	void addRole(final R role);

	/**
	 * Returns the field <code>id</code>.
	 *
	 * @return The field <code>id</code>.
	 */
	String getId();

	/**
	 * Returns the field <code>password</code>.
	 *
	 * @return The field <code>password</code>.
	 */
	String getPw();

	/**
	 * Returns the field <code>roles</code>.
	 *
	 * @return The field <code>roles</code>.
	 */
	Set<R> getRoles();

	/**
	 * Returns the field <code>username</code>.
	 *
	 * @return The field <code>username</code>.
	 */
	String getUsername();

	/**
	 * Checks if this User is active.
	 *
	 * @return true if the User is active otherwise false.
	 */
	Boolean isActive();

	/**
	 * Returns the field <code>lock</code>.
	 *
	 * @return The field <code>lock</code>.
	 */
	Boolean isLocked();

	/**
	 * Removes the given role from the user.
	 *
	 * @param role
	 *            the role
	 * @return true, if successful
	 */
	boolean removeRole(final R role);

	/**
	 * Sets the active flag.
	 *
	 * @param active
	 *            the new active flag.
	 */
	void setActive(final Boolean active);

	/**
	 * Sets the field <code>id</code>.
	 *
	 * @param id
	 *            The <code>id</code> to set
	 */
	void setId(final String id);

	/**
	 * Sets the field <code>lock</code>.
	 *
	 * @param locked
	 *            The <code>lock</code> to set
	 */
	void setLocked(final Boolean locked);

	/**
	 * Sets the field <code>password</code>.
	 *
	 * @param password
	 *            The <code>password</code> to set
	 */
	void setPw(final String password);

	/**
	 * Sets the field <code>roles</code>.
	 *
	 * @param roles
	 *            The <code>roles</code> to set
	 */
	void setRoles(final Set<R> roles);

	/**
	 * Sets the field <code>username</code>.
	 *
	 * @param username
	 *            The <code>username</code> to set
	 */
	void setUsername(final String username);

}