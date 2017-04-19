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

import java.util.Date;
import java.util.Locale;
import java.util.Map;

import de.alpharogroup.auth.interfaces.Permission;
import de.alpharogroup.auth.interfaces.Role;
import de.alpharogroup.auth.interfaces.Session;
import de.alpharogroup.auth.interfaces.User;
import de.alpharogroup.collections.InsertionOrderMap;
import de.alpharogroup.random.RandomObjectsExtensions;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

/**
 * The class {@link UserSession}.
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
public class UserSession implements Session<String, String>
{

	/**
	 * The serialVersionUID.
	 */
	private static final long serialVersionUID = -5792522256514467537L;

	/** The id. */
	private String id;

	/** The locale. */
	private Locale locale;

	/** The start time. */
	private Date startTime;

	/** The user. */
	private User<Permission, Role<Permission>> user;

	/** The last access. */
	private Date lastAccess;

	/** The max inactive time. */
	private int maxInactiveTime;

	/** The attributtes. */
	private Map<String, String> attributtes;

	/**
	 * Default constructor.
	 *
	 * @param user
	 *            The user
	 */
	public UserSession(final User<Permission, Role<Permission>> user)
	{
		if (null == user)
		{
			throw new IllegalArgumentException("User can't be null.");
		}
		this.user = user;
		this.initialize();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String getAttributte(final String key)
	{
		return attributtes.get(key);
	}

	/**
	 * Initialie the UserSession object.
	 */
	private void initialize()
	{
		this.id = RandomObjectsExtensions.newRandomId();
		this.startTime = new Date(System.currentTimeMillis());
		this.lastAccess = (Date)this.startTime.clone();
		this.maxInactiveTime = 180000;
		this.attributtes = new InsertionOrderMap<>();
		this.locale = Locale.getDefault();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String setAttribute(final String key, final String value)
	{
		return attributtes.put(key, value);
	}

}
