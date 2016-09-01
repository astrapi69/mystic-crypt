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
package de.alpharogroup.auth;

import de.alpharogroup.auth.interfaces.Permission;

/**
 * The Class SimpleAccessRight.
 *
 * @version 1.0
 * @author Asterios Raptis
 */
public class SimplePermission implements Permission
{

	/**
	 * The serialVersionUID.
	 */
	private static final long serialVersionUID = -1128896772349172908L;

	/** The name. */
	private String name;

	/** The description. */
	private String description;

	private String shortcut;

	/**
	 * {@inheritDoc}
	 *
	 * @return the description
	 * @see de.alpharogroup.auth.interfaces.Permission#getDescription()
	 */
	@Override
	public String getDescription()
	{
		return this.description;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @return the name
	 * @see de.alpharogroup.auth.interfaces.Permission#getPermissionName()
	 */
	@Override
	public String getPermissionName()
	{
		return this.name;
	}

	@Override
	public String getShortcut()
	{
		return this.shortcut;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @param description
	 *            the description
	 * @see de.alpharogroup.auth.interfaces.Permission#setDescription(java.lang.String)
	 */
	@Override
	public void setDescription(final String description)
	{
		this.description = description;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @param name
	 *            the name
	 * @see de.alpharogroup.auth.interfaces.Permission#setPermissionName(java.lang.String)
	 */
	@Override
	public void setPermissionName(final String name)
	{
		this.name = name;
	}

	@Override
	public void setShortcut(final String shortcut)
	{
		this.shortcut = shortcut;
	}

}
