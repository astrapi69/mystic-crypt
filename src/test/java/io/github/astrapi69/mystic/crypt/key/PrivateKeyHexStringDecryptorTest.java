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

import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertNotNull;

import java.io.File;
import java.security.PrivateKey;

import org.testng.annotations.Test;

import io.github.astrapi69.crypt.data.key.reader.PrivateKeyReader;
import io.github.astrapi69.file.search.PathFinder;

/**
 *
 * The unit test class for the class {@link PrivateKeyHexStringDecryptor}
 */
public class PrivateKeyHexStringDecryptorTest
{

	/**
	 * Test method for {@link PrivateKeyHexStringDecryptor#decrypt(String)}
	 *
	 * @throws Exception
	 *             is thrown if any error occurs
	 */
	@Test
	public void testDecrypt() throws Exception
	{
		String actual;
		String expected;
		PrivateKey privateKey;
		File derDir;
		File privatekeyDerFile;
		PrivateKeyHexStringDecryptor decryptor;
		String encypted;

		derDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		privatekeyDerFile = new File(derDir, "private.der");

		privateKey = PrivateKeyReader.readPrivateKey(privatekeyDerFile);

		decryptor = new PrivateKeyHexStringDecryptor(privateKey);
		assertNotNull(decryptor);
		encypted = "ACED000573720035696F2E6769746875622E6173747261706936392E63727970742E646174612E6D6F64656C2E41657352736143727970744D6F64656C00000000000000010200025B000C656E637279707465644B65797400025B425B001B73796D6D65747269634B6579456E637279707465644F626A65637471007E00017870757200025B42ACF317F8060854E0020000787000000100D49E860C31D23C5FF65BF06D54472CCB3F44116939D23C5A140C6AA235A6007CA930FF8BF70104151E5E283A4F11E2F535EC9D6C2E4B5D8D523B3E626BD09DBFE9D333E6BE363FA2C52C7A015D2495FF19F24F781528A145DCF17F6EC3FF6EAD5CD082853884603DA107B965F3260A8BB546D7A4E611023707D1FA048832C9785640D94FFC05A265798DF38C5B9BCBA11608F814809E952B783D3AF85C9C86FC1B212A5ADD667863723AC33AEC76938EA502A02A8D0ECC7F23EAA6B9391697F6D6F219ED65A9B012E76511D1B19CF3F79D84A7507126C42DAB16734B0468C8FA18DEAFA34AE286A65C882F2EB30001D239BD8E17121FBA92989FD7A6FB2411DC7571007E0003000000108B5E80A3C1903A265DBF8178B1D85C60";
		actual = decryptor.decrypt(encypted);
		assertNotNull(actual);
		expected = "foo";
		assertEquals(actual, expected);
	}
}