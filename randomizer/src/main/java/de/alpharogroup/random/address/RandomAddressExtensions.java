/**
 * Copyright (C) 2007 Asterios Raptis
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.alpharogroup.random.address;

import java.io.IOException;
import java.util.Properties;
import java.util.Set;

import de.alpharogroup.lang.PropertiesUtils;
import de.alpharogroup.random.RandomExtensions;

/**
 * Utility class to create random addresses.
 *
 * @version 1.0
 * @author Asterios Raptis
 */
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
		p = properties != null ? properties : PropertiesUtils.loadProperties(PROP_FILE_STREETS);
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