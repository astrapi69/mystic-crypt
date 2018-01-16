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
 * The interface {@link Role}.
 *
 * @version 1.0
 * @author Asterios Raptis
 * @param <T>
 *            the generic type
 */
public interface Role<T extends Permission> extends Serializable
{

	/**
	 * Returns the field <code>description</code>.
	 *
	 * @return The field <code>description</code>.
	 */
	String getDescription();

	/**
	 * Gets the access rights.
	 *
	 * @return the permissions
	 */
	Set<T> getPermissions();

	/**
	 * Gets the name.
	 *
	 * @return the name.
	 */
	String getRolename();

	/**
	 * Sets the field <code>description</code>.
	 *
	 * @param description
	 *            The <code>description</code> to set
	 */
	void setDescription(final String description);

	/**
	 * Sets the permissions.
	 *
	 * @param permissions
	 *            the new access rights.
	 */
	void setPermissions(final Set<T> permissions);

	/**
	 * Sets the name.
	 *
	 * @param name
	 *            the new name.
	 */
	void setRolename(final String name);

}