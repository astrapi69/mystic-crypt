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
package de.alpharogroup.random.api;

/**
 * The interface {@link NetworkGenerator} for generate random data like email, file names, urls,
 * domain names and other network elements.
 */
public interface NetworkGenerator
{

	/**
	 * New domainname.
	 *
	 * @return the string
	 */
	String newDomainname();

	/**
	 * New email.
	 *
	 * @return the string
	 */
	String newEmail();

	/**
	 * New filename.
	 *
	 * @return the string
	 */
	String newFilename();

	/**
	 * New ip address 4.
	 *
	 * @return the string
	 */
	String newIpAddress4();

	/**
	 * New ip address 6.
	 *
	 * @return the string
	 */
	String newIpAddress6();

	/**
	 * New mac address.
	 *
	 * @return the string
	 */
	String newMacAddress();

	/**
	 * New mime type.
	 *
	 * @return the string
	 */
	String newMimeType();

	/**
	 * New sha 1.
	 *
	 * @return the string
	 */
	String newSha1();

	/**
	 * New sha 256.
	 *
	 * @return the string
	 */
	String newSha256();

	/**
	 * New url.
	 *
	 * @return the string
	 */
	String newUrl();
}
