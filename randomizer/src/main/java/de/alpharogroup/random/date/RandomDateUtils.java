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
package de.alpharogroup.random.date;

import java.security.SecureRandom;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Random;

import de.alpharogroup.random.RandomUtils;
import de.alpharogroup.date.CalculateDateUtils;

/**
 * This util class gets random dates.
 *
 * @version 1.0
 * @author Asterios Raptis
 */
public class RandomDateUtils
{

	/**
	 * Creates a random date that is before from the given date.
	 *
	 * @param date
	 *            The date from where to compute the Past date.
	 * 
	 * @return The random Date in the past.
	 */
	public static Date dateBefore(Date date)
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
	public static Date dateBefore(Date date, int range)
	{
		return CalculateDateUtils.substractDaysFromDate(date, range);
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
	public static Date dateAfter(Date date, int range)
	{
		return CalculateDateUtils.addDays(date, RandomUtils.randomInt(range));
	}

	/**
	 * Creates a random Date that is after from the given Date.
	 *
	 * @param date
	 *            The Date from where to compute the future date.
	 * 
	 * @return The random Date in the future.
	 */
	public static Date dateAfter(Date date)
	{
		return dateAfter(date, RandomUtils.randomInt(10000));
	}

	/**
	 * Creates a random date.
	 *
	 * @param from
	 *            The date from where to begin.
	 * @return The random date.
	 */
	public static Date randomDate(Date from)
	{
		Random secrand = new SecureRandom();
		double randDouble = -secrand.nextDouble() * from.getTime();
		double randomDouble = from.getTime() - secrand.nextDouble();
		double result = randDouble / 99999 * (randomDouble / 99999);
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
	public static Date randomDatebetween(Date start, Date end)
	{
		Random secran = new SecureRandom();
		long randomLong = (long)(start.getTime() + secran.nextDouble()
			* (end.getTime() - start.getTime()));
		return new Date(randomLong);
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
	public static Date randomDateBetween(Date from, int startDays, int endDays)
	{
		return dateAfter(from, RandomUtils.randomIntBetween(startDays, endDays));
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
	public static String randomDatebetween(long startDate, long endDate, String format)
	{
		Random secrand = new SecureRandom();
		SimpleDateFormat sdf = new SimpleDateFormat(format);
		long randomLong = (long)(startDate + secrand.nextDouble() * (endDate - startDate));
		return sdf.format(new Date(randomLong));
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
	public static String randomDatebetween(long startDate, long endDate)
	{
		return randomDatebetween(startDate, endDate, "dd.MM.yyyy HH:mm:ss");
	}

	/**
	 * Creates a random birthday-date between 9 and 55 years.
	 *
	 * @return 's the random date.
	 */
	public static Date randomBirthday()
	{
		Date now = new Date(System.currentTimeMillis());
		// About 55 years.
		Date past = dateBefore(now, 20000);
		// About 9 years.
		Date recentlyPast = dateBefore(now, 3000);
		Date randomBirthday = randomBirthday(recentlyPast, past);
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
	public static Date randomBirthday(Date from, Date till)
	{
		Date randomBirthday = randomDatebetween(from, till);
		return randomBirthday;
	}


	/**
	 * Creates a java.sql.Timestamp(to match the ones in the database) from the given date.
	 * 
	 * @param date
	 *            The date
	 * 
	 * @return Timestamp.
	 */
	public static Timestamp getTimestamp(Date date)
	{
		Calendar gregCal = new GregorianCalendar();
		gregCal.setTime(date);
		gregCal.set(Calendar.HOUR_OF_DAY, 0);
		gregCal.set(Calendar.MINUTE, 0);
		gregCal.set(Calendar.SECOND, 0);
		gregCal.set(Calendar.MILLISECOND, 0);
		return new Timestamp(gregCal.getTime().getTime());
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

}
