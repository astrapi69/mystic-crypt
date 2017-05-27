package de.alpharogroup.crypto.key.reader;

import static org.testng.AssertJUnit.assertEquals;

import java.io.File;
import java.io.IOException;

import org.bouncycastle.util.io.pem.PemObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.annotations.Test;

import de.alpharogroup.file.search.PathFinder;


/**
 * Test class for the class {@link PemObjectReader}.
 */
public class PemObjectReaderTest
{
	/** The LOGGER. */
	static final Logger logger = LoggerFactory.getLogger(PemObjectReaderTest.class.getName());

	/**
	 * Test method for {@link PemObjectReader#getPemObject(File)}.
	 */
	@Test
	public void testGetPemObject() throws IOException
	{
		final File privatekeyPemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		final File privatekeyPemFile = new File(privatekeyPemDir, "private.pem");

		PemObject pemObject = PemObjectReader.getPemObject(privatekeyPemFile);
		String actual = pemObject.getType();
		String expected = "RSA PRIVATE KEY";
		assertEquals(expected, actual);

	}

	/**
	 * Test method for {@link PemObjectReader#toPemFormat(PemObject)}.
	 */
	@Test
	public void testToPemFormat()
	{
	}

}
