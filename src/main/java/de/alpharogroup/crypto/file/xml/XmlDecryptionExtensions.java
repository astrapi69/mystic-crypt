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
import java.util.Map;

import org.apache.commons.codec.DecoderException;

import com.thoughtworks.xstream.XStream;

import de.alpharogroup.crypto.hex.HexExtensions;
import de.alpharogroup.file.read.ReadFileExtensions;
import de.alpharogroup.xml.XmlToObjectExtensions;
import lombok.NonNull;
import lombok.experimental.UtilityClass;

/**
 * The class {@link XmlDecryptionExtensions} provides methods for read an encrypted file and decrypt
 * xml data.
 */
@UtilityClass
public class XmlDecryptionExtensions
{

	/**
	 * Read from file the data object that was before saved as xml and encoded into a hexadecimal
	 * {@link String} object.
	 *
	 * @param <T>
	 *            the generic type of the data object
	 * @param xstream
	 *            the {@link XStream} object
	 * @param aliases
	 *            the aliases for the {@link XStream} object
	 * @param selectedFile
	 *            the selected file to read
	 * @return the generic data object
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @throws DecoderException
	 *             is thrown if an odd number or illegal of characters is supplied
	 */
	public static <T> T readFromFileAsXmlAndHex(final @NonNull XStream xstream,
		final @NonNull Map<String, Class<?>> aliases, final @NonNull File selectedFile)
		throws IOException, DecoderException
	{
		final String hexXmlString = ReadFileExtensions.readFromFile(selectedFile);
		String xmlString = HexExtensions.decodeHex(hexXmlString);

		return XmlToObjectExtensions.toObjectWithXStream(xstream, xmlString, aliases);
	}

}
