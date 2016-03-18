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
package de.alpharogroup.auth.interfaces;

import java.io.Serializable;
import java.util.Date;
import java.util.Locale;
import java.util.Map;

/**
 * The Interface Session.
 *
 * @version 1.0
 *
 * @author Asterios Raptis
 * 
 * @param <K>
 *            the type of keys maintained by the attribute map
 * @param <V>
 *            the type of mapped values *
 *
 */
public interface Session<K, V> extends Serializable
{

	/**
	 * Returns the field <code>id</code>.
	 *
	 * @return The field <code>id</code>.
	 */
	String getId();

	/**
	 * Sets the field <code>id</code>.
	 *
	 * @param id
	 *            The <code>id</code> to set
	 */
	void setId(final String id);

	/**
	 * Returns the field <code>locale</code>.
	 *
	 * @return The field <code>locale</code>.
	 */
	Locale getLocale();

	/**
	 * Sets the field <code>locale</code>.
	 *
	 * @param locale
	 *            The <code>locale</code> to set
	 */
	void setLocale(final Locale locale);

	/**
	 * Returns the field <code>startTime</code>.
	 *
	 * @return The field <code>startTime</code>.
	 */
	Date getStartTime();

	/**
	 * Sets the field <code>startTime</code>.
	 *
	 * @param startTime
	 *            The <code>startTime</code> to set
	 */
	void setStartTime(final Date startTime);

	/**
	 * Returns the field <code>user</code>.
	 *
	 * @return The field <code>user</code>.
	 */
	User<Permission, Role<Permission>> getUser();

	/**
	 * Sets the field <code>user</code>.
	 *
	 * @param user
	 *            The <code>user</code> to set.
	 */
	void setUser(final User<Permission, Role<Permission>> user);

	/**
	 * Returns the field <code>lastAccess</code>.
	 *
	 * @return The field <code>lastAccess</code>.
	 */
	Date getLastAccess();

	/**
	 * Sets the field <code>lastAccess</code>.
	 *
	 * @param lastAccess
	 *            The <code>lastAccess</code> to set
	 */
	void setLastAccess(final Date lastAccess);

	/**
	 * Returns the field <code>maxInactiveTime</code>.
	 *
	 * @return The field <code>maxInactiveTime</code>.
	 */
	int getMaxInactiveTime();

	/**
	 * Sets the field <code>maxInactiveTime</code>.
	 *
	 * @param maxInactiveTime
	 *            The <code>maxInactiveTime</code> to set
	 */
	void setMaxInactiveTime(final int maxInactiveTime);

	/**
	 * Returns the field <code>attributtes</code>.
	 *
	 * @return The field <code>attributtes</code>.
	 */
	Map<K, V> getAttributtes();

	V getAttributte(final K key);

	V setAttribute(final K key, final V value);

	/**
	 * Sets the field <code>attributtes</code>.
	 *
	 * @param attributtes
	 *            The <code>attributtes</code> to set
	 */
	void setAttributtes(final Map<K, V> attributtes);

}