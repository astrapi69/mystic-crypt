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

/**
 * The interface {@link SessionContext}.
 *
 * @version 1.0
 *
 * @author Asterios Raptis
 *
 * @param <K>
 *            The Type for the Key.
 * @param <SK>
 *            the type of keys maintained by the session attribute map
 * @param <SV>
 *            the type of mapped values *
 */
public interface SessionContext<K, SK, SV> extends Serializable
{

	/**
	 * Adds the session to the context.
	 *
	 * @param session
	 *            the session
	 */
	void addSession(final Session<SK, SV> session);

	/**
	 * Gets the session from the given id.
	 *
	 * @param id
	 *            the id
	 * @return the session
	 */
	Session<SK, SV> getSession(final K id);

	/**
	 * Removes the session from the context.
	 *
	 * @param id
	 *            the id from the session to be removed.
	 */
	void removeSession(final K id);

}