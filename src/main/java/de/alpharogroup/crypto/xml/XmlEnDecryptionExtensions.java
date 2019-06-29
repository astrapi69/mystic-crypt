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
package de.alpharogroup.crypto.xml;

import java.io.File;
import java.io.IOException;
import java.util.Map;

import de.alpharogroup.crypto.file.xml.XmlDecryptionExtensions;
import de.alpharogroup.crypto.file.xml.XmlEncryptionExtensions;
import org.apache.commons.codec.DecoderException;

import com.thoughtworks.xstream.XStream;

import lombok.NonNull;
import lombok.experimental.UtilityClass;

/**
 * The class {@link XmlEnDecryptionExtensions} provides methods for write and encrypt and read and
 * decrypt xml data.
 * @deprecated use instead <code>XmlEncryptionExtensions</code> or <code>XmlDecryptionExtensions</code>
 * <br>Note: will be removed in next minor release
 */
@UtilityClass
public class XmlEnDecryptionExtensions
{

	/**
	 * Write the given data object to the given file as xml and encoded into a hexadecimal
	 * {@link String} object
	 *
	 * @param <T>
	 *            the generic type of the data object
	 * @param xstream
	 *            the xstream object
	 * @param aliases
	 *            the aliases for the xstream
	 * @param data
	 *            the data to write
	 * @param file
	 *            the file to write
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @deprecated use instead <code>XmlEncryptionExtensions</code> same name method
	 * <br>Note: will be removed in next minor release
	 */
	public static <T> void writeToFileAsXmlAndHex(final @NonNull XStream xstream,
		final @NonNull Map<String, Class<?>> aliases, final @NonNull T data, @NonNull File file)
		throws IOException
	{
		XmlEncryptionExtensions.writeToFileAsXmlAndHex(xstream, aliases, data, file);
	}

	/**
	 * Read from file the data object that was before saved as xml and encoded into a hexadecimal
	 * {@link String} object.
	 *
	 * @param <T>
	 *            the generic type of the data object
	 * @param xstream
	 *            the {@link XStream} object
	 * @param aliases
	 *            the aliases
	 * @param selectedFile
	 *            the selected file to read
	 * @return the generic data object
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @throws DecoderException
	 *             is thrown if an odd number or illegal of characters is supplied
	 * @deprecated use instead <code>XmlDecryptionExtensions</code> same name method
	 * <br>Note: will be removed in next minor release
	 */
	public static <T> T readFromFileAsXmlAndHex(final @NonNull XStream xstream,
		final @NonNull Map<String, Class<?>> aliases, final @NonNull File selectedFile)
		throws IOException, DecoderException
	{
		return XmlDecryptionExtensions.readFromFileAsXmlAndHex(xstream, aliases, selectedFile);
	}

}
