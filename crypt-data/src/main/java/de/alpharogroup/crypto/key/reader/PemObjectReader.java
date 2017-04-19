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
package de.alpharogroup.crypto.key.reader;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringWriter;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;

/**
 * The class {@link PemObjectReader} is a utility class for reading {@link PemObject} from a file.
 */
public class PemObjectReader
{

	/**
	 * Gets the pem object.
	 *
	 * @param file
	 *            the file
	 * @return the pem object
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static PemObject getPemObject(final File file) throws IOException
	{
		PemObject pemObject;
		final PemReader pemReader = new PemReader(new InputStreamReader(new FileInputStream(file)));
		try
		{
			pemObject = pemReader.readPemObject();
		}
		finally
		{
			pemReader.close();
		}
		return pemObject;
	}

	/**
	 * Transform the given {@link PemObject} object in pem format {@link String} object.
	 *
	 * @param pemObject
	 *            the pem object
	 * @return the string
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static String toPemFormat(final PemObject pemObject) throws IOException
	{
		final StringWriter stringWriter = new StringWriter();
		final PemWriter pemWriter = new PemWriter(stringWriter);
		pemWriter.writeObject(pemObject);
		pemWriter.close();
		final String pemString = stringWriter.toString();
		return pemString;
	}
}
