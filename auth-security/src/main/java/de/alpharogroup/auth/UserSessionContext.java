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

import java.util.LinkedHashMap;
import java.util.Map;

import de.alpharogroup.auth.interfaces.Session;
import de.alpharogroup.auth.interfaces.SessionContext;

/**
 * The Class UserSessionContext. Singleton object.
 *
 * @version 1.0
 * @author Asterios Raptis
 */
public class UserSessionContext implements SessionContext<String, String, String>
{

	/**
	 * The serialVersionUID.
	 */
	private static final long serialVersionUID = 6569927899638872741L;

	/** The instance. */
	private static final SessionContext<String, String, String> instance = new UserSessionContext();

	/**
	 * Returns the field <code>instance</code>.
	 *
	 * @return The field <code>instance</code>.
	 */
	public static SessionContext<String, String, String> getInstance()
	{

		return instance;
	}

	/** The online sessions. */
	private Map<String, Session<String, String>> onlineSessions = new LinkedHashMap<>();

	/**
	 * Instantiates a new user session context. It private.
	 */
	private UserSessionContext()
	{
		super();
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @see de.alpharogroup.auth.interfaces.SessionContext#addSession(de.alpharogroup.auth.interfaces.Session)
	 */
	@Override
	public synchronized void addSession(final Session<String, String> session)
	{
		this.onlineSessions.put(session.getId(), session);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @see de.alpharogroup.auth.interfaces.SessionContext#getSession(Object)
	 */
	@Override
	public synchronized Session<String, String> getSession(final String id)
	{
		if (this.onlineSessions.containsKey(id))
		{
			return this.onlineSessions.get(id);
		}
		return null;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @see de.alpharogroup.auth.interfaces.SessionContext#removeSession(Object)
	 */
	@Override
	public synchronized void removeSession(final String id)
	{
		if (this.onlineSessions.containsKey(id))
		{
			this.onlineSessions.remove(id);
		}
	}

}
