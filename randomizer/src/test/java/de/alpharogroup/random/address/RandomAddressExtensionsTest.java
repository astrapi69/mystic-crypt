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
/**
 *
 */
package de.alpharogroup.random.address;

import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import de.alpharogroup.BaseTestCase;

/**
 * Test class for the class RandomAddressExtensions.
 *
 * @version 1.0
 * @author Asterios Raptis
 */
public class RandomAddressExtensionsTest extends BaseTestCase
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
	 * {@link de.alpharogroup.random.address.RandomAddressExtensions#getRandomStreet(java.util.Properties)}
	 * .
	 */
	@Test
	public void testGetRandomStreet()
	{
		// final Properties germanstreets = ResourceUtils
		// .loadProperties( RandomAddressExtensions.PROP_FILE_STREETS );
		// final String germanStreet = RandomAddressExtensions
		// .getRandomStreet( germanstreets );
		// this.result = germanStreet != null;
		// assertTrue( "", this.result );
		//
		// this.result = germanstreets.contains( germanStreet );
		// assertTrue( "", this.result );
	}

	/**
	 * Test method for
	 * {@link de.alpharogroup.random.address.RandomAddressExtensions#getRandomStreetWithNumber(java.util.Properties)}
	 * .
	 */
	@Test
	public void testGetRandomStreetWithNumber()
	{
		// final Properties germanstreets = ResourceUtils
		// .loadProperties( RandomAddressExtensions.PROP_FILE_STREETS );
		// final String germanStreetWithNumber = RandomAddressExtensions
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
	 * {@link de.alpharogroup.random.address.RandomAddressExtensions#getRandomZip(java.util.Properties)}
	 * .
	 */
	@Test
	public void testGetRandomZip()
	{
		// final Properties germanzips = ResourceUtils
		// .loadProperties( RandomAddressExtensions.PROP_FILE_ZIP_CITIES );
		//
		// final String randomZip = RandomAddressExtensions.getRandomZip( germanzips );
		// this.result = randomZip != null;
		// assertTrue( "", this.result );
		//
		// this.result = StringUtils.isNumber( randomZip );
		// assertTrue( "", this.result );
	}

}
