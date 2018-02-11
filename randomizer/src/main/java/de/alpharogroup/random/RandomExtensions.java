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
package de.alpharogroup.random;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.text.DecimalFormat;
import java.text.NumberFormat;
import java.text.ParseException;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;

import de.alpharogroup.lang.ClassExtensions;
import lombok.experimental.UtilityClass;

/**
 * Utility class for producing random data. Existing name conventions:
 *
 * If the method starts with random* than it returns a primitive data type. If the method starts
 * with getRandom* than it returns an object.
 *
 * @version 1.1
 * @author Asterios Raptis
 */
@UtilityClass
public class RandomExtensions
{

	/** The secure random. */
	private static SecureRandom secureRandom;
	static
	{
		secureRandom = SecureRandomBean.builder().buildQuietly();
	}


	/**
	 * The Method randomLong() gets an long between the range 0-9.
	 *
	 * @return an long between the range 0-9.
	 */
	public static long randomLong()
	{
		return randomLong(new Random(System.currentTimeMillis()).nextInt());
	}

	/**
	 * The Method randomLong(long) gets an long to the spezified range. For example: if you put
	 * range to 10 the random int is between 0-9.
	 *
	 * @param range
	 *            the range
	 * @return an long not greater then the range.
	 */
	public static long randomLong(final long range)
	{
		if (secureRandom != null)
		{
			return (long)(secureRandom.nextDouble() * range);
		}
		return (long)(Math.random() * range);
	}

	/**
	 * Returns a random long between the range from start and end.
	 *
	 * @param start
	 *            The long from where the range starts.
	 * @param end
	 *            The long from where the range ends.
	 * @return A random long between the range from start and end.
	 */
	public static long randomLongBetween(final long start, final long end)
	{
		return start + randomLong(end - start);
	}

	/**
	 * Generates a random float between the range 0.0-9.9.
	 *
	 * @return the generated random float between the range 0.0-9.9.
	 */
	public static float randomFloat()
	{
		if (secureRandom != null)
		{
			return randomFloat(secureRandom.nextFloat());
		}
		return randomFloat(new Random(System.currentTimeMillis()).nextFloat());
	}

	/**
	 * Gets the secure random.
	 *
	 * @return the secure random
	 */
	public static SecureRandom getSecureRandom()
	{
		return secureRandom;
	}

	/**
	 * Generates a random int for use with pixel.
	 *
	 * @return a random int for use with pixel.
	 */
	public static int newRandomPixel()
	{
		return newRandomPixel(randomInt(256), randomInt(256), randomInt(256), randomInt(256));
	}

	/**
	 * Generates a random int for use with pixel.
	 *
	 * @param red
	 *            The red value.
	 * @param green
	 *            The green value.
	 * @param blue
	 *            The blue value.
	 * @param alpha
	 *            The alpha value.
	 * @return a random int for use with pixel.
	 */
	public static int newRandomPixel(final int red, final int green, final int blue,
		final int alpha)
	{
		final int pixel = (alpha << 24) | (red << 16) | (green << 8) | blue;
		return pixel;
	}

	/**
	 * The Method getRandomBigDecimal(int,int) gets an random BigDecimal.
	 *
	 * @param afterComma
	 *            How many decimal places after the comma.
	 * @param beforeComma
	 *            How many decimal places before the comma.
	 * @return The produced BigDecimal.
	 */
	public static BigDecimal getRandomBigDecimal(final int afterComma, final int beforeComma)
	{
		return new BigDecimal(getRandomFloatString(afterComma, beforeComma));
	}

	/**
	 * The Method getRandomByte() selects a random Byte object.
	 *
	 * @return The random Byte object.
	 */
	public static Byte getRandomByte()
	{
		return randomByte();
	}

	/**
	 * The Method getRandomByteArray(int) generates a random Byte array.
	 *
	 * @param length
	 *            the length.
	 * @return the Byte[]
	 */
	public static Byte[] getRandomByteArray(final int length)
	{
		final Byte[] randomByteArray = new Byte[length];
		final byte[] randomByteBox = new byte[1];
		for (int i = 0; i < length; i++)
		{
			if (randomBoolean())
			{
				randomByteArray[i] = getRandomByte();
			}
			else
			{
				secureRandom.nextBytes(randomByteBox);
				randomByteArray[i] = Byte.valueOf(randomByteBox[0]);
			}
		}
		return randomByteArray;
	}


	/**
	 * Returns a random entry from the given List.
	 *
	 * @param <T>
	 *            the generic type
	 * @param list
	 *            The List.
	 * @return Return's a random entry from the List.
	 */
	public static <T> T getRandomEntry(final List<T> list)
	{
		return list.get(getRandomIndex(list));
	}


	/**
	 * Returns a random entry from the given map.
	 *
	 * @param <K>
	 *            the key type
	 * @param <V>
	 *            the value type
	 * @param map
	 *            The map.
	 * @return Return's a random entry from the map.
	 */
	public static <K, V> Object getRandomEntry(final Map<K, V> map)
	{
		final Object[] entries = map.values().toArray();
		return entries[randomInt(entries.length)];
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
		return getRandomEnum(clazz.getEnumConstants());
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
	@SuppressWarnings("unchecked")
	public static <T extends Enum<?>> T getRandomEnum(final String classname)
	{
		if (classname != null && !classname.isEmpty())
		{
			Class<T> enumClass = null;
			try
			{
				enumClass = (Class<T>)ClassExtensions.forName(classname);
				return getRandomEnum(enumClass);
			}
			catch (final ClassNotFoundException e)
			{
				return null;
			}
		}
		return null;
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
	@SuppressWarnings("unchecked")
	public static <T extends Enum<?>> T getRandomEnum(final T obj)
	{
		if (obj != null)
		{
			final Class<T> clazz = (Class<T>)obj.getClass();
			return getRandomEnum(clazz);
		}
		return null;
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
		return values[randomInt(values.length)];
	}

	/**
	 * The Method getRandomFloat(int,int) gets an random float.
	 *
	 * @param afterComma
	 *            How many decimal places after the comma.
	 * @param beforeComma
	 *            How many decimal places before the comma.
	 * @return The produced float.
	 */
	public static Float getRandomFloat(final int afterComma, final int beforeComma)
	{
		return randomFloat(afterComma, beforeComma);
	}

	/**
	 * Gets the random float string.
	 *
	 * @param afterComma
	 *            How many decimal places after the comma.
	 * @param beforeComma
	 *            How many decimal places before the comma.
	 * @return the random float string
	 */
	private static String getRandomFloatString(final int afterComma, final int beforeComma)
	{
		final String nachkommastellen = getRandomNumericString(afterComma);
		final String vorkommastellen = getRandomNumericString(beforeComma);
		final String result = nachkommastellen + "." + vorkommastellen;
		return result;
	}

	/**
	 * Returns a random index from the given List.
	 *
	 * @param <T>
	 *            the generic type
	 * @param list
	 *            The List.
	 * @return Return's a random index from the List.
	 */
	public static <T> int getRandomIndex(final Collection<T> list)
	{
		return randomInt(list.size());
	}

	/**
	 * Returns a random key from the given map.
	 *
	 * @param <K>
	 *            the key type
	 * @param <V>
	 *            the value type
	 * @param map
	 *            The map.
	 * @return Return's a random key from the map.
	 */
	public static <K, V> Object getRandomKey(final Map<K, V> map)
	{
		final Set<K> keySet = map.keySet();
		final Object[] keys = keySet.toArray();
		return keys[randomInt(keys.length)];
	}

	/**
	 * Generates a random numeric string.
	 *
	 * @return the generated random numeric string.
	 */
	public static String getRandomNumericString()
	{
		final int maxLength = Math.min(randomInt(1000), 1024);
		final StringBuilder sb = new StringBuilder(maxLength);
		for (int i = 0; i < maxLength; i++)
		{
			sb.append(randomInt());
		}
		return sb.toString();
	}

	/**
	 * The Method getRandomNumericString(int) produces a random Number to the specified length.
	 *
	 * @param length
	 *            The length from the random number.
	 * @return The random number as String.
	 */
	public static String getRandomNumericString(final int length)
	{
		final String randomNumber = getRandomString(Constants.NUMBERS, length);
		return randomNumber;
	}

	/**
	 * Generates a random string.
	 *
	 * @param length
	 *            the specified length.
	 * @return the generated random string.
	 */
	public static String getRandomString(final int length)
	{
		final int maxLength = Math.min(length, 1024);
		final StringBuilder sb = new StringBuilder(maxLength);
		for (int i = 0; i < maxLength; i++)
		{
			sb.append(randomChar());
		}
		return sb.toString();
	}

	/**
	 * The Method randomString(String, int) makes an random String from the given String and to the
	 * spezified length. This can be used to produce passwords.
	 *
	 * @param chars
	 *            The String to get the random chars.
	 * @param length
	 *            The length from the random String.
	 * @return The produced random String.
	 */
	public static String getRandomString(final String chars, final int length)
	{
		final StringBuffer ergebnis = new StringBuffer();
		for (int i = 0; i < length; i++)
		{
			ergebnis.append(randomChar(chars));
		}
		return ergebnis.toString();
	}

	/**
	 * The Method randomString(String []) a random String from the Array For example: The
	 * Stringarray test as argument. Possible values: "blab", "flih", "klap", "teta", "brut",
	 * "gzft", "ccp". Possible selection can be one value from the Stringarray like "blab" or
	 * "klap".
	 *
	 * @param array
	 *            The array with the String to be selected.
	 * @return The selected String from the array.
	 */
	public static String getRandomString(final String[] array)
	{
		return array[randomInt(array.length)];
	}

	/**
	 * Returns a random boolean.
	 *
	 * @return The random boolean.
	 */
	public static boolean randomBoolean()
	{
		return randomInt(2) == 0;
	}

	/**
	 * The Method randomByte() selects a random byte.
	 *
	 * @return The random byte.
	 */
	public static byte randomByte()
	{
		return (byte)randomInt(255);
	}

	/**
	 * The Method randomByteArray(int) generates a random byte array.
	 *
	 * @param length
	 *            the length.
	 * @return the byte[]
	 */
	public static byte[] randomByteArray(final int length)
	{
		final byte[] randomByteArray = new byte[length];
		for (int i = 0; i < length; i++)
		{
			randomByteArray[i] = randomByte();
		}
		return randomByteArray;
	}

	/**
	 * Returns a random char.
	 *
	 * @return The generated random char.
	 */
	public static char randomChar()
	{
		if (secureRandom.nextBoolean())
		{
			// random character
			return (char)(secureRandom.nextInt(26) + 65);
		}
		else
		{
			// random digit
			return (char)secureRandom.nextInt(10);
		}
	}

	/**
	 * The Method randomChar(String) selects a random char from the given String.
	 *
	 * @param string
	 *            The String from who to select the char.
	 * @return The selected char.
	 */
	public static char randomChar(final String string)
	{
		return string.charAt(randomInt(string.length()));
	}


	/**
	 * The Method randomDouble(double) gets an double to the spezified range. For example: if you
	 * put range to 10.0 the random int is between 0.0-9.9.
	 *
	 * @param range
	 *            the range
	 * @return the double
	 */
	public static double randomDouble(final double range)
	{
		if (secureRandom != null)
		{
			return secureRandom.nextDouble() * range;
		}
		return Math.random() * range;
	}

	/**
	 * Gets the random double between the range from start and end.
	 *
	 * @param start
	 *            the start
	 * @param end
	 *            the end
	 * @return the random double between
	 */
	public static double randomDoubleBetween(final double start, final double end)
	{
		return start + randomDouble(end - start);
	}

	/**
	 * Gets the random double between the range from start and end in the given pattern. Refer to
	 * class @see {@link java.text.DecimalFormat}.
	 *
	 * @param start
	 *            the start
	 * @param end
	 *            the end
	 * @param pattern
	 *            the pattern
	 * @return the random double between
	 */
	public static double randomDoubleBetween(final double start, final double end,
		final String pattern)
	{
		final DecimalFormat formatter = new DecimalFormat(pattern);
		final String rd = formatter.format(randomDoubleBetween(start, end));
		try
		{
			return formatter.parse(rd).doubleValue();
		}
		catch (final ParseException e)
		{
			throw new NumberFormatException("Could not be parsed:" + rd);
		}
	}

	/**
	 * The Method randomFloat(float) gets an float to the spezified range. For example: if you put
	 * range to 10.0 the random int is between 0.0-9.9.
	 *
	 * @param range
	 *            the range
	 * @return the float
	 */
	public static float randomFloat(final float range)
	{
		if (secureRandom != null)
		{
			return (float)(secureRandom.nextDouble() * range);
		}
		return (float)(Math.random() * range);
	}

	/**
	 * The Method getRandomFloat(int,int) gets an random float.
	 *
	 * @param afterComma
	 *            How many decimal places after the comma.
	 * @param beforeComma
	 *            How many decimal places before the comma.
	 * @return The produced float.
	 */
	public static float randomFloat(final int afterComma, final int beforeComma)
	{
		return Float.parseFloat(getRandomFloatString(afterComma, beforeComma));
	}

	/**
	 * Gets the random float between the range from start and end.
	 *
	 * @param start
	 *            the start
	 * @param end
	 *            the end
	 * @return the random float between
	 */
	public static float randomFloatBetween(final float start, final float end)
	{
		return start + randomFloat(end - start);
	}

	/**
	 * Gets the random float between the range from start and end in the given pattern. Refer to
	 * class @see {@link java.text.DecimalFormat}.
	 *
	 * @param start
	 *            the start
	 * @param end
	 *            the end
	 * @param pattern
	 *            the pattern
	 * @return the random float between
	 */
	public static float randomFloatBetween(final float start, final float end, final String pattern)
	{
		final NumberFormat formatter = new DecimalFormat(pattern);
		final String rf = formatter.format(randomFloatBetween(start, end));
		try
		{
			return formatter.parse(rf).floatValue();
		}
		catch (final ParseException e)
		{
			throw new NumberFormatException("Could not be parsed:" + rf);
		}
	}

	/**
	 * The Method randomInt() gets an int between the range 0-9.
	 *
	 * @return an int between the range 0-9.
	 */
	public static int randomInt()
	{
		if (secureRandom != null)
		{
			return randomInt(secureRandom.nextInt());
		}
		return randomInt(new Random(System.currentTimeMillis()).nextInt());
	}

	/**
	 * The Method randomInt(int) gets an int to the spezified range. For example: if you put range
	 * to 10 the random int is between 0-9.
	 *
	 * @param range
	 *            The Range.
	 * @return an int not greater then the range.
	 */
	public static int randomInt(final int range)
	{
		if (secureRandom != null)
		{
			return (int)(secureRandom.nextDouble() * range);
		}
		return (int)(Math.random() * range);
	}

	/**
	 * Returns a random int between the range from start and end.
	 *
	 * @param start
	 *            The int from where the range starts.
	 * @param end
	 *            The int from where the range ends.
	 * @return A random int between the range from start and end.
	 */
	public static int randomIntBetween(final int start, final int end)
	{
		return start + randomInt(end - start);
	}

	/**
	 * Returns a random token for use in web services.
	 *
	 * @return A random token.
	 */
	public static String randomToken()
	{
		final BigInteger token = new BigInteger(130, RandomExtensions.getSecureRandom());
		final String randomToken = token.toString(32);
		return randomToken;
	}

	/**
	 * Returns a random serial number that can be used for a serial number.
	 *
	 * @return a random serial number as a {@link BigInteger} object.
	 */
	public static BigInteger randomSerialNumber()
	{
		long next = RandomExtensions.getSecureRandom().nextLong();
		if (next < 0)
		{
			next = next * (-1);
		}
		final BigInteger serialNumber = BigInteger.valueOf(next);
		return serialNumber;
	}

	/**
	 * The Method getRandomPrimitiveByteArray(int) generates a random byte array.
	 *
	 * @param length
	 *            the length.
	 * @return the byte[]
	 */
	public static byte[] getRandomPrimitiveByteArray(final int length)
	{
		final byte[] randomByteArray = new byte[length];
		final byte[] randomByteBox = new byte[1];
		for (int i = 0; i < length; i++)
		{
			if (randomBoolean())
			{
				randomByteArray[i] = getRandomByte();
			}
			else
			{
				secureRandom.nextBytes(randomByteBox);
				randomByteArray[i] = Byte.valueOf(randomByteBox[0]);
			}
		}
		return randomByteArray;
	}

	/**
	 * Factory method for create a new random salt.
	 *
	 * @return the byte[] with the new random salt.
	 */
	public static byte[] newSalt()
	{
		return getRandomPrimitiveByteArray(16);
	}

	/**
	 * Gets the random salt.
	 *
	 * @param length
	 *            the length
	 * @param charset
	 *            the charset
	 * @return the random salt
	 */
	public static byte[] getRandomSalt(final int length, final Charset charset)
	{
		return RandomExtensions.getRandomString(Constants.LCUCCHARSWN, length).getBytes(charset);
	}

}
