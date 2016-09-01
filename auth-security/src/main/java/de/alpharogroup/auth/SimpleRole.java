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

import java.util.Set;

import de.alpharogroup.auth.interfaces.Permission;
import de.alpharogroup.auth.interfaces.Role;

/**
 * The Class SimpleRole.
 *
 * @version 1.0
 * @author Asterios Raptis
 */
public class SimpleRole implements Role<Permission>
{

	/**
	 * The serialVersionUID.
	 */
	private static final long serialVersionUID = -5456020518185764323L;

	/** The name. */
	private String name;

	/** The permissions. */
	private Set<Permission> permissions;

	/** The description from the role. */
	private String description;

	/**
	 * Returns the field <code>description</code>.
	 *
	 * @return The field <code>description</code>.
	 */
	@Override
	public String getDescription()
	{
		return this.description;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @see de.alpharogroup.auth.interfaces.Role#getPermissions()
	 */
	@Override
	public Set<Permission> getPermissions()
	{
		return this.permissions;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @see de.alpharogroup.auth.interfaces.Role#getRolename()
	 */
	@Override
	public String getRolename()
	{
		return this.name;
	}


	/**
	 * Sets the field <code>description</code>.
	 *
	 * @param description
	 *            The <code>description</code> to set
	 */
	@Override
	public void setDescription(final String description)
	{
		this.description = description;
	}

	@Override
	public void setPermissions(final Set<Permission> permissions)
	{
		this.permissions = permissions;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void setRolename(final String name)
	{
		this.name = name;
	}

}
