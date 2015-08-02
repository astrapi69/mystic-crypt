/**
 * Copyright (C) 2007 Asterios Raptis
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.alpharogroup.crypto.aes;

import org.testng.AssertJUnit;
import org.testng.annotations.Test;

public class ChainedEncryptDecryptorTest
{


	@Test
	public void testChainedEncryptDecrypt() throws Exception
	{
		final String secretMessage = "I'm a very secret message and will be encrypted with the ChainedDecryptor;-)";
		System.out.println("String before encryption:");
		System.out.println(secretMessage);
		final String firstKey = "D1D15ED36B887AF1";
		final String secondKey = "44850AD044361AE8";
		final String thirdKey = "BD0F34C849772DC6";
		final HexEncryptor firstEncryptor = new HexEncryptor(firstKey);
		final HexEncryptor secondEncryptor = new HexEncryptor(secondKey);
		final HexEncryptor thirdEncryptor = new HexEncryptor(thirdKey);
		final ChainedEncryptor encryptor = new ChainedEncryptor(firstEncryptor, secondEncryptor,
			thirdEncryptor);

		final String encrypted = encryptor.encrypt(secretMessage);
		System.out.println("String after encryption:");
		System.out.println(encrypted);
		final HexDecryptor firstDecryptor = new HexDecryptor(firstKey);
		final HexDecryptor secondDecryptor = new HexDecryptor(secondKey);
		final HexDecryptor thirdDecryptor = new HexDecryptor(thirdKey);
		final ChainedDecryptor decryptor = new ChainedDecryptor(thirdDecryptor, secondDecryptor,
			firstDecryptor);

		final String decryted = decryptor.decrypt(encrypted);
		System.out.println("String after decryption:");
		System.out.println(decryted);
		AssertJUnit.assertTrue("String before encryption is not equal after decryption.",
			secretMessage.equals(decryted));
	}
}
