/**
 * Copyright (C) 2015 Asterios Raptis
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
package de.alpharogroup.random.date;

import java.util.Date;

import org.testng.AssertJUnit;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import de.alpharogroup.BaseTestCase;
import de.alpharogroup.date.CalculateDateExtensions;

/**
 * Test class for the class RandomDateExtensions.
 *
 * @version 1.0
 * @author Asterios Raptis
 */
public class RandomDateExtensionsTest extends BaseTestCase
{

	Date now = null;

	/**
	 * {@inheritDoc}
	 */
	@Override
	@BeforeMethod
	protected void setUp() throws Exception
	{
		super.setUp();
		this.now = new Date(System.currentTimeMillis());
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	@AfterMethod
	protected void tearDown() throws Exception
	{
		super.tearDown();
		this.now = null;
	}


	/**
	 * Test method for {@link de.alpharogroup.random.date.RandomDateExtensions#randomBirthday()}.
	 */
	@Test
	public void testCreateRandomBirthday()
	{
		// About 55 years.
		final Date past = RandomDateExtensions.dateBefore(this.now, 20000);
		// About 9 years.
		final Date recentlyPast = RandomDateExtensions.dateBefore(this.now, 3000);
		for (int i = 0; i < 100; i++)
		{
			final Date randomBirthday = RandomDateExtensions.randomBirthday();
			this.result = CalculateDateExtensions.isBetween(past, recentlyPast, randomBirthday);
			AssertJUnit.assertTrue("",
				CalculateDateExtensions.isBetween(past, recentlyPast, randomBirthday));
		}
	}

	/**
	 * Test method for
	 * {@link de.alpharogroup.random.date.RandomDateExtensions#randomBirthday(java.util.Date, java.util.Date)}
	 * .
	 */
	@Test
	public void testCreateRandomBirthdayDateDate()
	{
		final Date from = CalculateDateExtensions.substractDaysFromDate(this.now, 20000);
		final Date till = CalculateDateExtensions.substractDaysFromDate(this.now, 3000);
		for (int i = 0; i < 100; i++)
		{
			final Date randomBirthday = RandomDateExtensions.randomBirthday(from, till);
			this.result = CalculateDateExtensions.isBetween(from, till, randomBirthday);
			AssertJUnit.assertTrue("", this.result);
		}
	}

	/**
	 * Test method for
	 * {@link de.alpharogroup.random.date.RandomDateExtensions#randomDate(java.util.Date)}.
	 */
	@Test
	public void testCreateRandomDate()
	{

		final Date from = this.now;
		final Date randomDate = RandomDateExtensions.randomDate(from);
		this.result = randomDate != null;
		AssertJUnit.assertTrue("", this.result);

		this.result = !randomDate.equals(this.now);
		AssertJUnit.assertTrue("", this.result);

	}

	/**
	 * Test method for
	 * {@link de.alpharogroup.random.date.RandomDateExtensions#randomDateBetween(java.util.Date, int, int)}
	 * .
	 */
	@Test
	public void testCreateRandomDateBetween()
	{

		// final Date from = this.now;
		// final int startDays = 0;
		// final int endDays = 30;
		// final Date till = DateUtils.addDaysToDate( this.now, 30 );
		// final Date randomDate = RandomDateExtensions.createRandomDateBetween( from,
		// startDays, endDays );
		// this.result = DateUtils.isBetween( this.now, till, randomDate );
		// assertTrue( "", this.result );
	}

	/**
	 * Test method for
	 * {@link de.alpharogroup.random.date.RandomDateExtensions#randomDatebetween(java.util.Date, java.util.Date)}
	 * .
	 */
	@Test
	public void testCreateRandomDatebetweenDateDate()
	{
		// final Date end = DateUtils.addDaysToDate( this.now, 30 );
		// final Date start = this.now;
		// final Date randomDate = RandomDateExtensions.createRandomDatebetween( start,
		// end );
		// this.result = DateUtils.isBetween( start, end, randomDate );
		// assertTrue( "", this.result );
	}

	/**
	 * Test method for
	 * {@link de.alpharogroup.random.date.RandomDateExtensions#randomDatebetween(long, long)}.
	 */
	@Test
	public void testCreateRandomDatebetweenLongLong()
	{
		// final Date till = DateUtils.addDaysToDate( this.now, 30 );
		// final long endDate = till.getTime();
		// final long startDate = this.now.getTime();
		// final String randomDate = RandomDateExtensions.createRandomDatebetween(
		// startDate, endDate );
		// final Date compare = DateUtils.parseToDate( randomDate,
		// DatePatterns.DOT_DD_MM_YYYY_HH_MM_SS );
		// this.result = DateUtils.isBetween( this.now, till, compare );
		// assertTrue( "", this.result );
	}

	/**
	 * Test method for
	 * {@link de.alpharogroup.random.date.RandomDateExtensions#randomDatebetween(long, long, java.lang.String)}
	 * .
	 */
	@Test
	public void testCreateRandomDatebetweenLongLongString()
	{
		// final Date till = DateUtils.addDaysToDate( this.now, 30 );
		// final long endDate = till.getTime();
		// final long startDate = this.now.getTime();
		// final String format = DatePatterns.DOT_DD_MM_YY;
		// final String randomDate = RandomDateExtensions.createRandomDatebetween(
		// startDate, endDate, format );
		// final Date compare = DateUtils.parseToDate( randomDate, format );
		// this.result = DateUtils.isBetween( this.now, till, compare );
		// assertTrue( "", this.result );
	}

}
