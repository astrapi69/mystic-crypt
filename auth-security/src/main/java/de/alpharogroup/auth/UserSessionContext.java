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
package de.alpharogroup.auth;

import java.util.LinkedHashMap;
import java.util.Map;

import de.alpharogroup.auth.api.Session;
import de.alpharogroup.auth.api.SessionContext;

/**
 * The class {@link UserSessionContext}. Singleton object.
 *
 * @version 1.0
 * @author Asterios Raptis
 */
public class UserSessionContext implements SessionContext<String, String, String>
{

	/**
	 * The serialVersionUID.
	 */
	private static final long serialVersionUID = -7176164226848814834L;
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
	private final Map<String, Session<String, String>> onlineSessions = new LinkedHashMap<>();

	/**
	 * Instantiates a new {@link UserSessionContext}. Private constructor.
	 */
	private UserSessionContext()
	{
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public synchronized void addSession(final Session<String, String> session)
	{
		this.onlineSessions.put(session.getId(), session);
	}

	/**
	 * {@inheritDoc}
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
