/*
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
package io.github.astrapi69.mystic.crypt.pw;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Content that mystic-crypt-ui's file encryption window wrote, for the tests of the reader of both
 * formats (#306, astrapi69/mystic-crypt-ui#877). Not a replica: the window's own
 * {@code FileCryptSupport} of mystic-crypt-ui develop d45b4201 was compiled against
 * mystic-crypt-13.10.jar, the version that application builds with, and its {@code encryptFile} and
 * {@code encryptText} wrote these on 2026-11-14 with the passphrase below.
 */
public final class WindowFixtures
{

	/** The passphrase both were sealed with, made up for this fixture */
	public static final String PASSPHRASE = "window fixture passphrase";

	/**
	 * {@code encryptFile} of a file holding {@link #FILE_PLAINTEXT}: 127 bytes, the marker
	 * {@code MCFILE1}. Its last salt byte is 0x43, so read as an {@code MCFILE} its iteration count
	 * would be 1 124 075 815
	 */
	public static final String FILE = "TUNGSUxFMdZeY0sm26GwxiniTfQNbkMACSfAYHES2dGzTtULHLbRb0JyrwaavFfnX+dzNqz/CEFHipePEHwP0h"
		+ "Ptszlhq8vox+52O/uSA1GufHoQG4GlNyNOY9zsZmVakCuHpjvk9MVdHwdrD6nEoHRfPoZF2wRozNyJZW0v1g==";

	/** What the file held */
	public static final String FILE_PLAINTEXT = "a file the file encryption window sealed";

	/**
	 * {@code encryptText} of {@link #TEXT_PLAINTEXT}, which the window shows as Base64. Its last
	 * salt byte is 0xa5, so read as an {@code MCFILE} its iteration count would be negative
	 */
	public static final String TEXT = "TUNGSUxFMWJrRn61Vs0VCrav8DH226UACSfA4roloDiGmd8P30V4wHCPZvGJGFU8daOuvE8f7RErdaIBmxrKhx"
		+ "8qfhfwCOG81YnUsLgxjjY/josODw9qxUfdeIh3TCpV/9xEch8b9BUCMMABs1XUytcErUlKtOcHEY+ofcoT6w==";

	/** What the text was */
	public static final String TEXT_PLAINTEXT = "a text the file encryption window sealed";

	private WindowFixtures()
	{
	}

	/**
	 * The bytes of the file
	 *
	 * @return the decoded {@link #FILE}
	 */
	public static byte[] fileBytes()
	{
		return Base64.getDecoder().decode(FILE);
	}

	/**
	 * The bytes of the text
	 *
	 * @return the decoded {@link #TEXT}
	 */
	public static byte[] textBytes()
	{
		return Base64.getDecoder().decode(TEXT);
	}

	/**
	 * The plaintext of the file
	 *
	 * @return {@link #FILE_PLAINTEXT} as UTF-8 bytes
	 */
	public static byte[] filePlaintext()
	{
		return FILE_PLAINTEXT.getBytes(StandardCharsets.UTF_8);
	}
}
