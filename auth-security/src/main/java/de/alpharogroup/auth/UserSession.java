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

import java.util.Date;
import java.util.Locale;
import java.util.Map;

import de.alpharogroup.auth.interfaces.Permission;
import de.alpharogroup.auth.interfaces.Role;
import de.alpharogroup.auth.interfaces.Session;
import de.alpharogroup.auth.interfaces.User;
import de.alpharogroup.collections.InsertionOrderMap;
import de.alpharogroup.random.RandomObjectsUtils;

/**
 * The Class UserSession.
 *
 * @version 1.0
 * @author Asterios Raptis
 */
public class UserSession implements Session<String, String>
{

	/**
	 * The serialVersionUID.
	 */
	private static final long serialVersionUID = 2858590853976767758L;

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

	@Override
	public String getAttributte(final String key)
	{
		return attributtes.get(key);
	}

	/**
	 * {@inheritDoc}
	 *
	 * @see de.alpharogroup.auth.interfaces.Session#getAttributtes()
	 */
	@Override
	public Map<String, String> getAttributtes()
	{
		if (null == this.attributtes)
		{
			this.attributtes = new InsertionOrderMap<>();
		}
		return this.attributtes;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @see de.alpharogroup.auth.interfaces.Session#getId()
	 */
	@Override
	public String getId()
	{
		return this.id;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @see de.alpharogroup.auth.interfaces.Session#getLastAccess()
	 */
	@Override
	public Date getLastAccess()
	{
		return (Date)this.lastAccess.clone();
	}

	/**
	 * {@inheritDoc}
	 *
	 * @see de.alpharogroup.auth.interfaces.Session#getLocale()
	 */
	@Override
	public Locale getLocale()
	{
		return this.locale;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @see de.alpharogroup.auth.interfaces.Session#getMaxInactiveTime()
	 */
	@Override
	public int getMaxInactiveTime()
	{
		return this.maxInactiveTime;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @see de.alpharogroup.auth.interfaces.Session#getStartTime()
	 */
	@Override
	public Date getStartTime()
	{
		return (Date)this.startTime.clone();
	}

	/**
	 * {@inheritDoc}
	 *
	 * @see de.alpharogroup.auth.interfaces.Session#getUser()
	 */
	@Override
	public User<Permission, Role<Permission>> getUser()
	{
		return this.user;
	}

	/**
	 * Initialie the UserSession object.
	 */
	private void initialize()
	{
		this.id = RandomObjectsUtils.newRandomId();
		this.startTime = new Date(System.currentTimeMillis());
		this.lastAccess = (Date)this.startTime.clone();
		this.maxInactiveTime = 180000;
		this.attributtes = new InsertionOrderMap<>();
		this.locale = Locale.getDefault();
	}

	@Override
	public String setAttribute(final String key, final String value)
	{
		return attributtes.put(key, value);
	}

	/**
	 * {@inheritDoc}
	 *
	 * @see de.alpharogroup.auth.interfaces.Session#setAttributtes(java.util.Map)
	 */
	@Override
	public void setAttributtes(final Map<String, String> attributtes)
	{
		this.attributtes = attributtes;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @see de.alpharogroup.auth.interfaces.Session#setId(java.lang.String)
	 */
	@Override
	public void setId(final String id)
	{
		this.id = id;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @see de.alpharogroup.auth.interfaces.Session#setLastAccess(java.util.Date)
	 */
	@Override
	public void setLastAccess(final Date lastAccess)
	{
		this.lastAccess = (Date)lastAccess.clone();
	}

	/**
	 * {@inheritDoc}
	 *
	 * @see de.alpharogroup.auth.interfaces.Session#setLocale(java.util.Locale)
	 */
	@Override
	public void setLocale(final Locale locale)
	{
		this.locale = locale;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @see de.alpharogroup.auth.interfaces.Session#setMaxInactiveTime(int)
	 */
	@Override
	public void setMaxInactiveTime(final int maxInactiveTime)
	{
		this.maxInactiveTime = maxInactiveTime;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @see de.alpharogroup.auth.interfaces.Session#setStartTime(java.util.Date)
	 */
	@Override
	public void setStartTime(final Date startTime)
	{
		this.startTime = (Date)startTime.clone();
	}

	/**
	 * {@inheritDoc}
	 *
	 * @see de.alpharogroup.auth.interfaces.Session#setUser(de.alpharogroup.auth.interfaces.User)
	 */
	@Override
	public void setUser(final User<Permission, Role<Permission>> user)
	{
		this.user = user;
	}

}
