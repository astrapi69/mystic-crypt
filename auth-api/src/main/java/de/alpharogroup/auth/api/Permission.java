/**
 * The MIT License
 *
 * Copyright (C) 2015 Asterios Raptis
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
 * associated documentation files (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge, publish, distribute,
 * sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or
 * substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
 * NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package de.alpharogroup.auth.api;

import java.io.Serializable;

/**
 * The interface {@link Permission}.
 */
public interface Permission extends Serializable
{

	/**
	 * Returns the field <code>description</code>.
	 *
	 * @return The field <code>description</code>.
	 */
	String getDescription();

	/**
	 * Returns the field <code>name</code>.
	 *
	 * @return The field <code>name</code>.
	 */
	String getPermissionName();

	/**
	 * Gets the shortcut.
	 *
	 * @return the shortcut
	 */
	String getShortcut();

	/**
	 * Sets the field <code>description</code>.
	 *
	 * @param description
	 *            The <code>description</code> to set
	 */
	void setDescription(final String description);

	/**
	 * Sets the field <code>name</code>.
	 *
	 * @param name
	 *            The <code>name</code> to set
	 */
	void setPermissionName(final String name);

	/**
	 * Sets the shortcut.
	 *
	 * @param shortcut
	 *            the new shortcut
	 */
	void setShortcut(final String shortcut);

}