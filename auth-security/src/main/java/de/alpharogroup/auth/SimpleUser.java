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

import de.alpharogroup.auth.api.Permission;
import de.alpharogroup.auth.api.Role;
import de.alpharogroup.auth.api.User;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.Singular;
import lombok.ToString;

/**
 * The class {@link SimpleUser}.
 *
 * @version 1.0
 * @author Asterios Raptis
 */
@Getter
@Setter
@EqualsAndHashCode
@ToString
@NoArgsConstructor
@AllArgsConstructor
@Builder(toBuilder = true)
public class SimpleUser implements User<Permission, Role<Permission>>
{
	/**
	 * The serialVersionUID.
	 */
	private static final long serialVersionUID = -5529415990423317979L;

	/** The attribute active, if true the user account is active. */
	private Boolean active;
	/** The username. */
	private String username;

	/** The username. */
	private String pw;

	/** The id. */
	private String id;

	/** The roles. */
	@Singular
	private Set<Role<Permission>> roles;

	/** Flag if the user is locked. */
	private Boolean locked;

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void addRole(final Role<Permission> role)
	{
		this.roles.add(role);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Boolean isActive()
	{
		return active;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Boolean isLocked()
	{
		return this.locked;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean removeRole(final Role<Permission> role)
	{
		return this.roles.remove(role);
	}

}
