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
package de.alpharogroup.crypto.file.xml;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Map;

import com.thoughtworks.xstream.XStream;

import de.alpharogroup.crypto.hex.HexExtensions;
import de.alpharogroup.file.write.WriteFileExtensions;
import de.alpharogroup.xml.ObjectToXmlExtensions;
import lombok.NonNull;
import lombok.experimental.UtilityClass;

/**
 * The class {@link XmlEncryptionExtensions} provides methods for encrypt data object to the given
 * file as xml and encoded into a hexadecimal {@link String} object
 */
@UtilityClass
public class XmlEncryptionExtensions
{

	/**
	 * Write the given data object to the given file as xml and encoded into a hexadecimal
	 * {@link String} object
	 *
	 * @param <T>
	 *            the generic type of the data object
	 * @param xstream
	 *            the {@link XStream} object
	 * @param aliases
	 *            the aliases for the {@link XStream} object
	 * @param data
	 *            the data to write
	 * @param file
	 *            the file to write
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static <T> void writeToFileAsXmlAndHex(final @NonNull XStream xstream,
		final @NonNull Map<String, Class<?>> aliases, final @NonNull T data, @NonNull File file)
		throws IOException
	{
		String xmlString = ObjectToXmlExtensions.toXmlWithXStream(xstream, data, aliases);
		final String hexXmlString = HexExtensions.encodeHex(xmlString, Charset.forName("UTF-8"),
			true);
		WriteFileExtensions.writeStringToFile(file, hexXmlString, "UTF-8");
	}

}
