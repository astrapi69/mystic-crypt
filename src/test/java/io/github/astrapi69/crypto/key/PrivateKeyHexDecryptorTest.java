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
package io.github.astrapi69.crypto.key;

import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertNotNull;

import java.io.File;
import java.security.PrivateKey;

import org.testng.annotations.Test;

import io.github.astrapi69.crypto.key.reader.PrivateKeyReader;
import io.github.astrapi69.file.search.PathFinder;

/**
 *
 * The unit test class for the class {@link PrivateKeyHexDecryptor}
 */
public class PrivateKeyHexDecryptorTest
{

	/**
	 * Test method for {@link PrivateKeyHexDecryptor} constructors
	 *
	 * @throws Exception
	 *             is thrown if any error occurs
	 */
	@Test
	public void testConstructors() throws Exception
	{
		String actual;
		String expected;
		PrivateKey privateKey;
		File derDir;
		File privatekeyDerFile;
		PrivateKeyHexDecryptor decryptor;
		String encypted;

		derDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		privatekeyDerFile = new File(derDir, "private.der");

		privateKey = PrivateKeyReader.readPrivateKey(privatekeyDerFile);

		decryptor = new PrivateKeyHexDecryptor(privateKey);
		assertNotNull(decryptor);
		encypted = "ACED000573720031696F2E6769746875622E6173747261706936392E63727970746F2E6D6F64656C2E41657352736143727970744D6F64656C00000000000000010200025B000C656E637279707465644B65797400025B425B001B73796D6D65747269634B6579456E637279707465644F626A65637471007E00017870757200025B42ACF317F8060854E00200007870000001001A4D3AE68958C7F057155542ED8913CCC9E27A10B6B20DAE22A9D93AAB8074C54B9B22A90F7F38549608027DC86684C56033725309FFA6C7D9E77464FDCA82AA2C7F925FA3BF136AB8314AF981BD89B56DF6B4046EAB7EA65844BFD3D33AC45168C1894F62FC6693CAF6C0E8834E634C2679693787ADA132434C43A9C828882B659379C039076E7BC193780A229CED9656066FC147674CAAB5BCD0E4676501068A5E78D16E042A81F9D3B0EDC493B90051F401B2C222A7E3037DCE1DBD80FDFF9AE6D016BE37548788A2C9E137343A2B36E3D4C60C554BFC04838CEA5407EC2EAD8CE3086B248EC8E6D987C1FAA6FD3F8EE2FB91C3C1316D39855FDD85F8CDDB7571007E000300000010F91E2212D00DB79DC6B306705DDC9B88";
		actual = decryptor.decrypt(encypted);
		assertNotNull(actual);
		expected = "foo";
		assertEquals(actual, expected);
	}
}
