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
package de.alpharogroup.random;

import java.math.BigDecimal;
import java.sql.Timestamp;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Map;

import de.alpharogroup.random.date.RandomDateExtensions;

/**
 * The Class DataGenerator.
 */
public final class DataGenerator
{

	/**
	 * Date after.
	 *
	 * @param date
	 *            the date
	 * @return the date
	 */
	public static Date dateAfter(final Date date)
	{
		return RandomDateExtensions.dateAfter(date);
	}

	/**
	 * Date after.
	 *
	 * @param date
	 *            the date
	 * @param range
	 *            the range
	 * @return the date
	 */
	public static Date dateAfter(final Date date, final int range)
	{
		return RandomDateExtensions.dateAfter(date, range);
	}

	/**
	 * Date before.
	 *
	 * @param date
	 *            the date
	 * @return the date
	 */
	public static Date dateBefore(final Date date)
	{
		return RandomDateExtensions.dateBefore(date);
	}

	/**
	 * Date before.
	 *
	 * @param date
	 *            the date
	 * @param range
	 *            the range
	 * @return the date
	 */
	public static Date dateBefore(final Date date, final int range)
	{
		return RandomDateExtensions.dateBefore(date, range);
	}

	/**
	 * Gets the random big decimal.
	 *
	 * @param afterComma
	 *            the after comma
	 * @param beforeComma
	 *            the before comma
	 * @return the random big decimal
	 */
	public static BigDecimal getRandomBigDecimal(final int afterComma, final int beforeComma)
	{
		return RandomExtensions.getRandomBigDecimal(afterComma, beforeComma);
	}

	/**
	 * Gets the random byte.
	 *
	 * @return the random byte
	 */
	public static Byte getRandomByte()
	{
		return RandomExtensions.getRandomByte();
	}

	/**
	 * Gets the random byte array.
	 *
	 * @param length
	 *            the length
	 * @return the random byte array
	 */
	public static Byte[] getRandomByteArray(final int length)
	{
		return RandomExtensions.getRandomByteArray(length);
	}

	/**
	 * Gets the random entry.
	 *
	 * @param <T>
	 *            the generic type
	 * @param list
	 *            the list
	 * @return the random entry
	 */
	public static <T> T getRandomEntry(final List<T> list)
	{
		return RandomExtensions.getRandomEntry(list);
	}

	/**
	 * Gets the random entry.
	 *
	 * @param <K>
	 *            the key type
	 * @param <V>
	 *            the value type
	 * @param map
	 *            the map
	 * @return the random entry
	 */
	public static <K, V> Object getRandomEntry(final Map<K, V> map)
	{
		return RandomExtensions.getRandomEntry(map);
	}

	/**
	 * Gets the random enum.
	 *
	 * @param <T>
	 *            the generic type
	 * @param clazz
	 *            the clazz
	 * @return the random enum
	 */
	public static <T extends Enum<?>> T getRandomEnum(final Class<T> clazz)
	{
		return RandomExtensions.getRandomEnum(clazz);
	}

	/**
	 * Gets the random enum.
	 *
	 * @param <T>
	 *            the generic type
	 * @param classname
	 *            the classname
	 * @return the random enum
	 */
	public static <T extends Enum<?>> T getRandomEnum(final String classname)
	{
		return RandomExtensions.getRandomEnum(classname);
	}

	/**
	 * Gets the random enum.
	 *
	 * @param <T>
	 *            the generic type
	 * @param obj
	 *            the obj
	 * @return the random enum
	 */
	public static <T extends Enum<?>> T getRandomEnum(final T obj)
	{
		return RandomExtensions.getRandomEnum(obj);
	}

	/**
	 * Gets the random enum.
	 *
	 * @param <T>
	 *            the generic type
	 * @param values
	 *            the values
	 * @return the random enum
	 */
	public static <T extends Enum<?>> T getRandomEnum(final T[] values)
	{
		return RandomExtensions.getRandomEnum(values);
	}

	/**
	 * Gets the random float.
	 *
	 * @param afterComma
	 *            the after comma
	 * @param beforeComma
	 *            the before comma
	 * @return the random float
	 */
	public static Float getRandomFloat(final int afterComma, final int beforeComma)
	{
		return RandomExtensions.getRandomFloat(afterComma, beforeComma);
	}

	/**
	 * Gets the random index.
	 *
	 * @param <T>
	 *            the generic type
	 * @param list
	 *            the list
	 * @return the random index
	 */
	public static <T> int getRandomIndex(final Collection<T> list)
	{
		return RandomExtensions.getRandomIndex(list);
	}

	/**
	 * Gets the random key.
	 *
	 * @param <K>
	 *            the key type
	 * @param <V>
	 *            the value type
	 * @param map
	 *            the map
	 * @return the random key
	 */
	public static <K, V> Object getRandomKey(final Map<K, V> map)
	{
		return RandomExtensions.getRandomKey(map);
	}

	/**
	 * Gets the random numeric string.
	 *
	 * @return the random numeric string
	 */
	public static String getRandomNumericString()
	{
		return RandomExtensions.getRandomNumericString();
	}

	/**
	 * Gets the random numeric string.
	 *
	 * @param length
	 *            the length
	 * @return the random numeric string
	 */
	public static String getRandomNumericString(final int length)
	{
		return RandomExtensions.getRandomNumericString(length);
	}

	/**
	 * Gets the random string.
	 *
	 * @param length
	 *            the length
	 * @return the random string
	 */
	public static String getRandomString(final int length)
	{
		return RandomExtensions.getRandomString(length);
	}

	/**
	 * Gets the random string.
	 *
	 * @param chars
	 *            the chars
	 * @param length
	 *            the length
	 * @return the random string
	 */
	public static String getRandomString(final String chars, final int length)
	{
		return RandomExtensions.getRandomString(chars, length);
	}

	/**
	 * Gets the random string.
	 *
	 * @param array
	 *            the array
	 * @return the random string
	 */
	public static String getRandomString(final String[] array)
	{
		return RandomExtensions.getRandomString(array);
	}

	/**
	 * Gets the timestamp.
	 *
	 * @return the timestamp
	 */
	public static Timestamp getTimestamp()
	{
		return RandomDateExtensions.getTimestamp();
	}

	/**
	 * Gets the timestamp.
	 *
	 * @param date
	 *            the date
	 * @return the timestamp
	 */
	public static Timestamp getTimestamp(final Date date)
	{
		return RandomDateExtensions.getTimestamp(date);
	}

	/**
	 * Random birthday.
	 *
	 * @return the date
	 */
	public static Date randomBirthday()
	{
		return RandomDateExtensions.randomBirthday();
	}

	/**
	 * Random birthday.
	 *
	 * @param from
	 *            the from
	 * @param till
	 *            the till
	 * @return the date
	 */
	public static Date randomBirthday(final Date from, final Date till)
	{
		return RandomDateExtensions.randomBirthday(from, till);
	}

	/**
	 * Random boolean.
	 *
	 * @return true, if successful
	 */
	public static boolean randomBoolean()
	{
		return RandomExtensions.randomBoolean();
	}

	/**
	 * Random byte.
	 *
	 * @return the byte
	 */
	public static byte randomByte()
	{
		return RandomExtensions.randomByte();
	}

	/**
	 * Random byte array.
	 *
	 * @param length
	 *            the length
	 * @return the byte[]
	 */
	public static byte[] randomByteArray(final int length)
	{
		return RandomExtensions.randomByteArray(length);
	}

	/**
	 * Random char.
	 *
	 * @return the char
	 */
	public static char randomChar()
	{
		return RandomExtensions.randomChar();
	}

	/**
	 * Random char.
	 *
	 * @param string
	 *            the string
	 * @return the char
	 */
	public static char randomChar(final String string)
	{
		return RandomExtensions.randomChar(string);
	}

	/**
	 * Random date.
	 *
	 * @param from
	 *            the from
	 * @return the date
	 */
	public static Date randomDate(final Date from)
	{
		return RandomDateExtensions.randomDate(from);
	}

	/**
	 * Random datebetween.
	 *
	 * @param start
	 *            the start
	 * @param end
	 *            the end
	 * @return the date
	 */
	public static Date randomDatebetween(final Date start, final Date end)
	{
		return RandomDateExtensions.randomDatebetween(start, end);
	}

	/**
	 * Random datebetween.
	 *
	 * @param startDate
	 *            the start date
	 * @param endDate
	 *            the end date
	 * @return the string
	 */
	public static String randomDatebetween(final long startDate, final long endDate)
	{
		return RandomDateExtensions.randomDatebetween(startDate, endDate);
	}

	/**
	 * Random datebetween.
	 *
	 * @param startDate
	 *            the start date
	 * @param endDate
	 *            the end date
	 * @param format
	 *            the format
	 * @return the string
	 */
	public static String randomDatebetween(final long startDate, final long endDate,
		final String format)
	{
		return RandomDateExtensions.randomDatebetween(startDate, endDate, format);
	}

	/**
	 * Random date between.
	 *
	 * @param from
	 *            the from
	 * @param startDays
	 *            the start days
	 * @param endDays
	 *            the end days
	 * @return the date
	 */
	public static Date randomDateBetween(final Date from, final int startDays, final int endDays)
	{
		return RandomDateExtensions.randomDateBetween(from, startDays, endDays);
	}

	/**
	 * Random double.
	 *
	 * @param range
	 *            the range
	 * @return the double
	 */
	public static double randomDouble(final double range)
	{
		return RandomExtensions.randomDouble(range);
	}

	/**
	 * Random double between.
	 *
	 * @param start
	 *            the start
	 * @param end
	 *            the end
	 * @return the double
	 */
	public static double randomDoubleBetween(final double start, final double end)
	{
		return RandomExtensions.randomDoubleBetween(start, end);
	}

	/**
	 * Random double between.
	 *
	 * @param start
	 *            the start
	 * @param end
	 *            the end
	 * @param pattern
	 *            the pattern
	 * @return the double
	 */
	public static double randomDoubleBetween(final double start, final double end,
		final String pattern)
	{
		return RandomExtensions.randomDoubleBetween(start, end, pattern);
	}

	/**
	 * Random float.
	 *
	 * @param range
	 *            the range
	 * @return the float
	 */
	public static float randomFloat(final float range)
	{
		return RandomExtensions.randomFloat(range);
	}

	/**
	 * Random float.
	 *
	 * @param afterComma
	 *            the after comma
	 * @param beforeComma
	 *            the before comma
	 * @return the float
	 */
	public static float randomFloat(final int afterComma, final int beforeComma)
	{
		return RandomExtensions.randomFloat(afterComma, beforeComma);
	}

	/**
	 * Random float between.
	 *
	 * @param start
	 *            the start
	 * @param end
	 *            the end
	 * @return the float
	 */
	public static float randomFloatBetween(final float start, final float end)
	{
		return RandomExtensions.randomFloatBetween(start, end);
	}

	/**
	 * Random float between.
	 *
	 * @param start
	 *            the start
	 * @param end
	 *            the end
	 * @param pattern
	 *            the pattern
	 * @return the float
	 */
	public static float randomFloatBetween(final float start, final float end, final String pattern)
	{
		return RandomExtensions.randomFloatBetween(start, end, pattern);
	}

	/**
	 * Random int.
	 *
	 * @return the int
	 */
	public static int randomInt()
	{
		return RandomExtensions.randomInt();
	}

	/**
	 * Random int.
	 *
	 * @param range
	 *            the range
	 * @return the int
	 */
	public static int randomInt(final int range)
	{
		return RandomExtensions.randomInt(range);
	}

	/**
	 * Random int between.
	 *
	 * @param start
	 *            the start
	 * @param end
	 *            the end
	 * @return the int
	 */
	public static int randomIntBetween(final int start, final int end)
	{
		return RandomExtensions.randomIntBetween(start, end);
	}

	/**
	 * Private constructor.
	 */
	private DataGenerator()
	{
	}


}
