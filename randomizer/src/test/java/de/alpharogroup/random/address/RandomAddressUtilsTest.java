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
/**
 *
 */
package de.alpharogroup.random.address;

import de.alpharogroup.BaseTestCase;

import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

/**
 * Test class for the class RandomAddressUtils.
 *
 * @version 1.0
 * @author Asterios Raptis
 */
public class RandomAddressUtilsTest extends BaseTestCase
{


	/**
	 * {@inheritDoc}
	 */
	@Override
	@BeforeMethod
	protected void setUp() throws Exception
	{
		super.setUp();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	@AfterMethod
	protected void tearDown() throws Exception
	{
		super.tearDown();
	}

	/**
	 * Test method for
	 * {@link de.alpharogroup.random.address.RandomAddressUtils#getRandomStreet(java.util.Properties)}
	 * .
	 */
	@Test
	public void testGetRandomStreet()
	{
		// final Properties germanstreets = ResourceUtils
		// .loadProperties( RandomAddressUtils.PROP_FILE_STREETS );
		// final String germanStreet = RandomAddressUtils
		// .getRandomStreet( germanstreets );
		// this.result = germanStreet != null;
		// assertTrue( "", this.result );
		//
		// this.result = germanstreets.contains( germanStreet );
		// assertTrue( "", this.result );
	}

	/**
	 * Test method for
	 * {@link de.alpharogroup.random.address.RandomAddressUtils#getRandomStreetWithNumber(java.util.Properties)}
	 * .
	 */
	@Test
	public void testGetRandomStreetWithNumber()
	{
		// final Properties germanstreets = ResourceUtils
		// .loadProperties( RandomAddressUtils.PROP_FILE_STREETS );
		// final String germanStreetWithNumber = RandomAddressUtils
		// .getRandomStreetWithNumber( germanstreets );
		// this.result = germanStreetWithNumber != null;
		// assertTrue( "", this.result );
		// final String lastChar = germanStreetWithNumber.substring(
		// germanStreetWithNumber.length() - 1, germanStreetWithNumber
		// .length() );
		// this.result = StringUtils.isNumber( lastChar );
		// assertTrue( "", this.result );
	}

	/**
	 * Test method for
	 * {@link de.alpharogroup.random.address.RandomAddressUtils#getRandomZip(java.util.Properties)}
	 * .
	 */
	@Test
	public void testGetRandomZip()
	{
		// final Properties germanzips = ResourceUtils
		// .loadProperties( RandomAddressUtils.PROP_FILE_ZIP_CITIES );
		//
		// final String randomZip = RandomAddressUtils.getRandomZip( germanzips );
		// this.result = randomZip != null;
		// assertTrue( "", this.result );
		//
		// this.result = StringUtils.isNumber( randomZip );
		// assertTrue( "", this.result );
	}

}
