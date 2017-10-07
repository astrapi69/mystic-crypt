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
package de.alpharogroup.random.address;

import java.io.IOException;
import java.util.Properties;
import java.util.Set;

import de.alpharogroup.random.RandomExtensions;
import de.alpharogroup.resourcebundle.properties.PropertiesFileExtensions;
import lombok.experimental.UtilityClass;

/**
 * The class {@link RandomAddressExtensions} is a utility class to create random addresses.
 *
 * @version 1.0
 * @author Asterios Raptis
 */
@UtilityClass
public class RandomAddressExtensions
{

	/** Resource for get german streets. */
	public static final String PROP_FILE_STREETS = "/resources/germanstreets.properties";

	/** Resource for get german zipcodes and the cities from it. */
	public static final String PROP_FILE_ZIP_CITIES = "/resources/de_zip_city.properties";

	/**
	 * Returns a random german street.
	 *
	 * @param properties
	 *            The properties file with the streets.
	 *
	 * @return A random german street.
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static String getRandomStreet(final Properties properties) throws IOException
	{
		Properties p = null;
		p = properties != null
			? properties
			: PropertiesFileExtensions.loadProperties(PROP_FILE_STREETS);
		final int size = p.size();
		final Object[] keys = p.keySet().toArray();
		final String street = (String)p.get(keys[RandomExtensions.randomInt(size)]);
		return street;
	}

	/**
	 * Gets a random german street with a random number.
	 *
	 * @param properties
	 *            The properties file with the streets.
	 *
	 * @return Returns a random german street with a random number.
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static String getRandomStreetWithNumber(final Properties properties) throws IOException
	{
		final String street = getRandomStreet(properties);
		final String streetWithNumber = street + " " + RandomExtensions.randomInt(200);
		return streetWithNumber;
	}

	/**
	 * Gets a random zip from the Properties.
	 *
	 * @param p
	 *            The Properties.
	 * @return Returns a random zip.
	 */
	public static String getRandomZip(final Properties p)
	{
		final Set<Object> keyset = p.keySet();
		final Object[] keys = keyset.toArray();
		final int randomIndex = RandomExtensions.randomInt(keys.length);
		final String zip = (String)keys[randomIndex];
		return zip;
	}

}