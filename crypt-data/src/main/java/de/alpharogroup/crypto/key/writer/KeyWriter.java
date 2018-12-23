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
package de.alpharogroup.crypto.key.writer;

import java.io.File;
import java.io.IOException;
import java.io.StringWriter;
import java.security.Key;

import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

import de.alpharogroup.file.write.WriteFileExtensions;
import lombok.NonNull;
import lombok.experimental.UtilityClass;

/**
 * The class {@link KeyWriter} is a utility class for write security keys in files.
 */
@UtilityClass
public class KeyWriter
{

	/**
	 * Write the given {@link Key} into the given {@link File}.
	 *
	 * @param key
	 *            the security key
	 * @param file
	 *            the file to write in
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static void writeInPemFormat(final Key key, final @NonNull File file) throws IOException
	{
		StringWriter stringWriter = new StringWriter();
		JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter);
		pemWriter.writeObject(key);
		pemWriter.close();
		String pemFormat = stringWriter.toString();
		pemFormat = pemFormat.replaceAll("\\r\\n", "\\\n");
		WriteFileExtensions.string2File(file, pemFormat);
	}

}
