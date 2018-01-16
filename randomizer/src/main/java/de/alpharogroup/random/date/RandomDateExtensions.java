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
package de.alpharogroup.random.date;

import java.security.SecureRandom;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Random;

import de.alpharogroup.date.CalculateDateExtensions;
import de.alpharogroup.random.RandomExtensions;
import lombok.experimental.UtilityClass;

/**
 * The class {@link RandomDateExtensions} is a utility class for creating random random dates.
 *
 * @version 1.0
 * @author Asterios Raptis
 */
@UtilityClass
public class RandomDateExtensions
{

	/**
	 * Creates a random Date that is after from the given Date.
	 *
	 * @param date
	 *            The Date from where to compute the future date.
	 *
	 * @return The random Date in the future.
	 */
	public static Date dateAfter(final Date date)
	{
		return dateAfter(date, RandomExtensions.randomInt(10000));
	}

	/**
	 * Creates a random Date that is after from the given Date.
	 *
	 * @param date
	 *            The Date from where to compute the future date.
	 * @param range
	 *            The range.
	 *
	 * @return The random Date in the future.
	 */
	public static Date dateAfter(final Date date, final int range)
	{
		return CalculateDateExtensions.addDays(date, RandomExtensions.randomInt(range));
	}

	/**
	 * Creates a random date that is before from the given date.
	 *
	 * @param date
	 *            The date from where to compute the Past date.
	 *
	 * @return The random Date in the past.
	 */
	public static Date dateBefore(final Date date)
	{
		return dateBefore(date, 10000);
	}

	/**
	 * Creates a random date that is before from the given date.
	 *
	 * @param date
	 *            The date from where to compute the past date.
	 * @param range
	 *            The range.
	 *
	 * @return The random Date in the past.
	 */
	public static Date dateBefore(final Date date, final int range)
	{
		return CalculateDateExtensions.substractDaysFromDate(date, range);
	}

	/**
	 * Creates a java.sql.Timestamp from now.
	 *
	 * @return Timestamp.
	 */
	public static Timestamp getTimestamp()
	{
		return getTimestamp(new Date());
	}

	/**
	 * Creates a java.sql.Timestamp(to match the ones in the database) from the given date.
	 *
	 * @param date
	 *            The date
	 *
	 * @return Timestamp.
	 */
	public static Timestamp getTimestamp(final Date date)
	{
		final Calendar gregCal = new GregorianCalendar();
		gregCal.setTime(date);
		gregCal.set(Calendar.HOUR_OF_DAY, 0);
		gregCal.set(Calendar.MINUTE, 0);
		gregCal.set(Calendar.SECOND, 0);
		gregCal.set(Calendar.MILLISECOND, 0);
		return new Timestamp(gregCal.getTime().getTime());
	}

	/**
	 * Creates a random birthday-date between 9 and 55 years.
	 *
	 * @return 's the random date.
	 */
	public static Date randomBirthday()
	{
		final Date now = new Date(System.currentTimeMillis());
		// About 55 years.
		final Date past = dateBefore(now, 20000);
		// About 9 years.
		final Date recentlyPast = dateBefore(now, 3000);
		final Date randomBirthday = randomBirthday(recentlyPast, past);
		return randomBirthday;
	}

	/**
	 * Creates a random birthday-date between the two given date-objects.
	 *
	 * @param from
	 *            The date from where to start.
	 * @param till
	 *            The date from where to end.
	 * @return 's the random date.
	 */
	public static Date randomBirthday(final Date from, final Date till)
	{
		final Date randomBirthday = randomDatebetween(from, till);
		return randomBirthday;
	}

	/**
	 * Creates a random date.
	 *
	 * @param from
	 *            The date from where to begin.
	 * @return The random date.
	 */
	public static Date randomDate(final Date from)
	{
		final Random secrand = new SecureRandom();
		final double randDouble = -secrand.nextDouble() * from.getTime();
		final double randomDouble = from.getTime() - secrand.nextDouble();
		final double result = (randDouble / 99999) * (randomDouble / 99999);
		return new Date((long)result);
	}

	/**
	 * Creates a random Date between the range from start and end.
	 *
	 * @param start
	 *            The Date from where the range starts.
	 * @param end
	 *            The Date from where the range ends.
	 * @return A random Date between the range from start and end.
	 */
	public static Date randomDatebetween(final Date start, final Date end)
	{
		final Random secran = new SecureRandom();
		final long randomLong = (long)(start.getTime()
			+ (secran.nextDouble() * (end.getTime() - start.getTime())));
		return new Date(randomLong);
	}

	/**
	 * Creates a random Date between the range from startDays and endDays from the given Date and
	 * gives it back as a string to the default "dd.MM.yyyy HH:mm:ss" format.
	 *
	 * @param startDate
	 *            The date from where to start as a long.
	 * @param endDate
	 *            The date from where to end as a long.
	 * @return The random date as a String.
	 */
	public static String randomDatebetween(final long startDate, final long endDate)
	{
		return randomDatebetween(startDate, endDate, "dd.MM.yyyy HH:mm:ss");
	}


	/**
	 * Creates a random Date between the range from startDays and endDays from the given Date and
	 * gives it back as a string to the given format.
	 *
	 * @param startDate
	 *            The date from where to start as a long.
	 * @param endDate
	 *            The date from where to end as a long.
	 * @param format
	 *            The format for the date.
	 * @return The random date as a String.
	 */
	public static String randomDatebetween(final long startDate, final long endDate,
		final String format)
	{
		final SimpleDateFormat sdf = new SimpleDateFormat(format);
		long randomLongBetween = RandomExtensions.randomLongBetween(startDate, endDate);
		Date between = new Date(randomLongBetween);
		return sdf.format(between);
	}


	/**
	 * Creates a random Date between the range from startDays and endDays from the given Date.
	 *
	 * @param from
	 *            The Date from where to the random Date to start.
	 * @param startDays
	 *            The int that represents the days from where the range starts.
	 * @param endDays
	 *            The int that represents the days from where the range ends.
	 * @return A random Date between the range from startDays and endDays from the given Date.
	 */
	public static Date randomDateBetween(final Date from, final int startDays, final int endDays)
	{
		return dateAfter(from, RandomExtensions.randomIntBetween(startDays, endDays));
	}

}
