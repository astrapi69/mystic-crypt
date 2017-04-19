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

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * The class {@link RandomObjectsExtensions} is a utility class to create random objects.
 */
public class RandomObjectsExtensions
{

	/**
	 * Gets an infomail address from the given url.
	 *
	 * @param url
	 *            The url.
	 * @return Returns an infomail address from the given url.
	 */
	public static String getInfomailFromWebsite(final String url)
	{
		int startIndex = url.indexOf("www.");
		final StringBuilder email = new StringBuilder();
		if (0 < startIndex)
		{
			final String emailprefix = "info";
			email.append(emailprefix);
			email.append("@");
			email.append(url.substring(startIndex + 4, url.length()));
		}
		else
		{
			startIndex = url.indexOf("//");
			if (0 < startIndex)
			{
				final String emailprefix = "info";
				email.append(emailprefix);
				email.append("@");
				email.append(url.substring(startIndex + 2, url.length()));
			}
			else
			{
				throw new IllegalArgumentException(url);
			}
		}
		return email.toString();
	}

	/**
	 * The Method getRandomEmail() gets a random email-address.
	 *
	 * @return The random email-address.
	 */
	public static String getRandomEmail()
	{
		final StringBuffer email = new StringBuffer();
		final String emailprefix = RandomExtensions.getRandomString(Constants.LCCHARSWN,
			RandomExtensions.randomInt(20) + 1);
		final String domain = RandomExtensions.getRandomString(Constants.LOWCASECHARS,
			RandomExtensions.randomInt(12) + 1);
		final String topDomain = RandomExtensions.getRandomString(Constants.LOWCASECHARS, 2);
		email.append(emailprefix);
		email.append("@");
		email.append(domain);
		email.append(".");
		email.append(topDomain);
		return email.toString();
	}

	/**
	 * Gets a random faxnumber from a phone.
	 *
	 * @param phonenumber
	 *            The phonenumber.
	 * @return Return's a random faxnumber from a phone.
	 */
	public static String getRandomFaxnumber(final String phonenumber)
	{
		final StringBuffer sb = new StringBuffer();
		final String randomFax = phonenumber.substring(0, phonenumber.length() - 2);
		sb.append(randomFax);
		final String phoneExtension = phonenumber.substring(phonenumber.length() - 2,
			phonenumber.length());
		final Integer phEx = new Integer(phoneExtension);
		final int pe = phEx + 1;
		sb.append(pe);
		return sb.toString();
	}

	/**
	 * Gets a random mobil number from a mobilphone.
	 *
	 * @return Return's a random mobil number from a mobilphone.
	 */
	public static String getRandomMobilnumber()
	{
		final StringBuffer randomPhonenumber = new StringBuffer();
		randomPhonenumber.append("0");
		randomPhonenumber.append(RandomExtensions.getRandomNumericString(3));
		randomPhonenumber.append("/");
		randomPhonenumber.append(RandomExtensions.getRandomNumericString(7));
		return randomPhonenumber.toString();
	}

	/**
	 * The Method getRandomPassword(int) produces a random password.
	 *
	 * @param length
	 *            The length from the password.
	 * @return The password.
	 */
	public static String getRandomPassword(final int length)
	{
		final String password = RandomExtensions.getRandomString(Constants.LCUCCHARSWN, length);
		return password;
	}

	/**
	 * The Method getRandomPassword(int) produces a random password.
	 *
	 * @param length
	 *            The length from the password as Optional.
	 * @return The password.
	 */
	public static String getRandomPassword(final Optional<Integer> length)
	{
		if (length.isPresent())
		{
			final String password = RandomExtensions.getRandomString(Constants.LCUCCHARSWN,
				length.get());
			return password;
		}
		return RandomExtensions.getRandomString(Constants.LCUCCHARSWN, 8);
	}

	/**
	 * Gets a random phonenumber.
	 *
	 * @return Return's a random phonenumber.
	 */
	public static String getRandomPhonenumber()
	{
		final StringBuffer randomPhonenumber = new StringBuffer();
		randomPhonenumber.append("0");
		randomPhonenumber.append(RandomExtensions.getRandomNumericString(4));
		randomPhonenumber.append("/");
		randomPhonenumber.append(RandomExtensions.getRandomNumericString(7));
		return randomPhonenumber.toString();
	}

	/**
	 * Gets a random name for a website.
	 *
	 * @return Returns a random name for a website.
	 */
	public static String getRandomWebsite()
	{
		final StringBuffer website = new StringBuffer();
		final String websitePrefix = "http://www";
		final String domain = RandomExtensions.getRandomString(Constants.LOWCASECHARS,
			RandomExtensions.randomInt(12) + 1);
		final String topDomain = RandomExtensions.getRandomString(Constants.LOWCASECHARS, 2);
		website.append(websitePrefix);
		website.append(".");
		website.append(domain);
		website.append(".");
		website.append(topDomain);
		return website.toString();
	}

	/**
	 * Creates a random id and returns it.
	 *
	 * @return the created random id.
	 */
	public static String newRandomId()
	{
		final StringBuffer sb = new StringBuffer();
		sb.append(RandomExtensions.getRandomString(Constants.LCUCCHARSWN, 2));
		sb.append(".");
		sb.append(RandomExtensions.getRandomString(Constants.LCUCCHARSWN, 4));
		sb.append(".");
		sb.append(RandomExtensions.getRandomString(Constants.LCUCCHARSWN, 2));
		sb.append(".");
		sb.append(System.currentTimeMillis());
		sb.append(".");
		sb.append(RandomExtensions.getRandomString(Constants.LCUCCHARSWN, 2));
		return sb.toString();
	}

	/**
	 * Creates a random Name from the donated chararray.
	 *
	 * @param donatedChars
	 *            The Characters for the name.
	 * @return A random Name.
	 */
	public static String newRandomName(final char[] donatedChars)
	{
		final StringBuffer sb = new StringBuffer(donatedChars.length);
		final List<Character> dc = new ArrayList<>(donatedChars.length);
		for (final char donatedChar : donatedChars)
		{
			dc.add(donatedChar);
		}
		boolean fullList = true;
		while (fullList)
		{
			final int randomIndex = RandomExtensions.randomInt(dc.size());
			final Character c = dc.get(randomIndex);
			sb.append(c);
			dc.remove(randomIndex);
			if (dc.isEmpty())
			{
				fullList = false;
			}
		}
		return sb.toString();
	}

}
