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
package io.github.astrapi69.mystic.crypt.key;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.File;
import java.security.PrivateKey;

import org.junit.jupiter.api.Test;

import io.github.astrapi69.crypt.data.key.reader.PrivateKeyReader;
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
		encypted = "ACED000573720035696F2E6769746875622E6173747261706936392E63727970742E646174612E6D6F64656C2E41657352736143727970744D6F64656C00000000000000010200025B000C656E637279707465644B65797400025B425B001B73796D6D65747269634B6579456E637279707465644F626A65637471007E00017870757200025B42ACF317F8060854E002000078700000010070C16DFFA2AD6679421B978D36CB4CBE8C9EF32B239B2D7972A62DF2BA67B7EE435F161C5843463072F974EBFEF5064CB97638B0DC8A7F47B74EB8F04FD2D0E01B7CB24B59FE72644AB78700A3352462BFC6491800F74A84BA4949DEDF06B6DDF5D977110AB5E48C44449DEE59D971F1511D530B5E5316C7E468D89FA076164A6357A80C656566D7EE1C11BC8AC01952EB185B909939CAE8B5EC90BE2D8D6853C9C9D0A0215BAC44662093D8D1EE26D49A1496D3DB7DF37AF4D3DEE26137567E06C9D71C4EF6B25620173F3D78D859720E3807B0E8F51785D8311FEE7A9EC53497D8C6B20E951D3158863EFAFC5BABF0D67D9A817FC442E8D4C150FF20A295CD7571007E0003000000100DB6F03FD2D284AF4D1F4BA1092FE507";
		actual = decryptor.decrypt(encypted);
		assertNotNull(actual);
		expected = "foo";
		assertEquals(actual, expected);
	}
}
