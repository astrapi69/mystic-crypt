package de.alpharogroup.crypto.file.xml;

import com.thoughtworks.xstream.XStream;
import de.alpharogroup.crypto.hex.HexExtensions;
import de.alpharogroup.file.write.WriteFileExtensions;
import de.alpharogroup.xml.ObjectToXmlExtensions;
import lombok.NonNull;
import lombok.experimental.UtilityClass;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Map;

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
