package de.alpharogroup.crypto.file.xml;

import com.thoughtworks.xstream.XStream;
import de.alpharogroup.crypto.hex.HexExtensions;
import de.alpharogroup.file.read.ReadFileExtensions;
import de.alpharogroup.xml.XmlToObjectExtensions;
import lombok.NonNull;
import lombok.experimental.UtilityClass;
import org.apache.commons.codec.DecoderException;

import java.io.File;
import java.io.IOException;
import java.util.Map;

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
