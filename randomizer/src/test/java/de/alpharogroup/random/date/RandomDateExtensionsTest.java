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
package de.alpharogroup.random.date;

import java.text.ParseException;
import java.util.Date;

import org.testng.AssertJUnit;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import de.alpharogroup.BaseTestCase;
import de.alpharogroup.date.CalculateDateExtensions;
import de.alpharogroup.date.DatePatterns;
import de.alpharogroup.date.ParseDateExtensions;

/**
 * The unit test class for the class {@link RandomDateExtensions}.
 *
 * @version 1.0
 * @author Asterios Raptis
 */
public class RandomDateExtensionsTest extends BaseTestCase
{

	/** The date for now. */
	private Date now;

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
	 * Test method for {@link RandomDateExtensions#randomBirthday()}.
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
	 * Test method for {@link RandomDateExtensions#randomBirthday(java.util.Date, java.util.Date)} .
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
	 * Test method for {@link RandomDateExtensions#randomDate(java.util.Date)}.
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
	 * Test method for {@link RandomDateExtensions#randomDateBetween(java.util.Date, int, int)} .
	 */
	@Test
	public void testCreateRandomDateBetween()
	{
		final Date from = this.now;
		final int startDays = 0;
		final int endDays = 30;
		final Date till = CalculateDateExtensions.addDays(this.now, 30);
		final Date randomDate = RandomDateExtensions.randomDateBetween(from, startDays, endDays);
		this.result = CalculateDateExtensions.isBetween(this.now, till, randomDate);
		AssertJUnit.assertTrue("", this.result);
	}

	/**
	 * Test method for
	 * {@link RandomDateExtensions#randomDatebetween(java.util.Date, java.util.Date)} .
	 */
	@Test
	public void testCreateRandomDatebetweenDateDate()
	{
		final Date end = CalculateDateExtensions.addDays(this.now, 30);
		final Date start = this.now;
		final Date randomDate = RandomDateExtensions.randomDatebetween(start, end);
		this.result = CalculateDateExtensions.isBetween(start, end, randomDate);
		AssertJUnit.assertTrue("", this.result);
	}

	/**
	 * Test method for {@link RandomDateExtensions#randomDatebetween(long, long)}.
	 *
	 * @throws ParseException
	 *             occurs when their are problems with parsing the String to Date.
	 */
	@Test
	public void testCreateRandomDatebetweenLongLong() throws ParseException
	{
		final Date till = CalculateDateExtensions.addDays(this.now, 30);
		final long endDate = till.getTime();
		final long startDate = this.now.getTime();
		final String randomDate = RandomDateExtensions.randomDatebetween(startDate, endDate);
		final Date compare = ParseDateExtensions.parseToDate(randomDate,
			DatePatterns.DOT_DD_MM_YYYY_HH_MM_SS);
		this.result = CalculateDateExtensions.isBetween(this.now, till, compare);
		AssertJUnit.assertTrue("", this.result);
	}

	/**
	 * Test method for {@link RandomDateExtensions#randomDatebetween(long, long, java.lang.String)}
	 * .
	 *
	 * @throws ParseException
	 *             occurs when their are problems with parsing the String to Date.
	 */
	@Test
	public void testCreateRandomDatebetweenLongLongString() throws ParseException
	{
		final Date from = CalculateDateExtensions.substractDaysFromDate(this.now, 1);
		final Date till = CalculateDateExtensions.addDays(this.now, 30);
		final long endDate = till.getTime();
		final long startDate = from.getTime();
		final String format = DatePatterns.DOT_DD_MM_YYYY_HH_MM_SS;
		final String randomDate = RandomDateExtensions.randomDatebetween(startDate, endDate,
			format);
		final Date compare = ParseDateExtensions.parseToDate(randomDate, format);
		this.result = CalculateDateExtensions.isBetween(from, till, compare);
		AssertJUnit.assertTrue("", this.result);
	}

}
