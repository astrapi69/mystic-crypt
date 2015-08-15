/**
 * The MIT License
 *
 * Copyright (C) 2007 Asterios Raptis
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

import java.util.HashSet;
import java.util.Set;

import de.alpharogroup.auth.interfaces.Permission;
import de.alpharogroup.auth.interfaces.Role;
import de.alpharogroup.auth.interfaces.User;

/**
 * The Class SimpleUser.
 *
 * @version 1.0
 * @author Asterios Raptis
 */
public class SimpleUser implements User<Permission, Role<Permission>>
{

	/**
	 * The serialVersionUID.
	 */
	private static final long serialVersionUID = 8255560614886684003L;
	/** The attribute active, if true the user account is active. */
	private Boolean active;
	/** The username. */
	private String username;

	/** The username. */
	private String pw;

	/** The id. */
	private String id;

	/** The roles. */
	private Set<Role<Permission>> roles = new HashSet<>();

	/** Flag if the user is locked. */
	private Boolean locked;

	@Override
	public void addRole(final Role<Permission> role)
	{
		this.roles.add(role);
	}

	/**
	 * {@inheritDoc}
	 *
	 * @see de.alpharogroup.auth.interfaces.User#getId()
	 */
	@Override
	public String getId()
	{
		return this.id;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @see de.alpharogroup.auth.interfaces.User#getPw()
	 */
	@Override
	public String getPw()
	{
		return this.pw;
	}

	@Override
	public Set<Role<Permission>> getRoles()
	{
		return this.roles;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @see de.alpharogroup.auth.interfaces.User#getUsername()
	 */
	@Override
	public String getUsername()
	{
		return this.username;
	}

	@Override
	public Boolean isActive()
	{
		return this.active;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @see de.alpharogroup.auth.interfaces.User#isLocked()
	 */
	@Override
	public Boolean isLocked()
	{
		return this.locked;
	}

	@Override
	public boolean removeRole(final Role<Permission> role)
	{
		return this.roles.remove(role);
	}

	@Override
	public void setActive(final Boolean active)
	{
		this.active = active;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @see de.alpharogroup.auth.interfaces.User#setId(java.lang.String)
	 */
	@Override
	public void setId(final String id)
	{
		this.id = id;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void setLocked(final Boolean lock)
	{
		this.locked = lock;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void setPw(final String password)
	{
		this.pw = password;
	}

	@Override
	public void setRoles(final Set<Role<Permission>> roles)
	{
		this.roles = roles;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @see de.alpharogroup.auth.interfaces.User#setUsername(java.lang.String)
	 */
	@Override
	public void setUsername(final String username)
	{
		this.username = username;
	}

}
