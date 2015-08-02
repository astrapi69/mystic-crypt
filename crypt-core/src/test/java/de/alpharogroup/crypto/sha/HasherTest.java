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
package de.alpharogroup.crypto.sha;

import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.testng.AssertJUnit;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import de.alpharogroup.crypto.algorithm.HashAlgorithm;

public class HasherTest
{

	@BeforeMethod
	public void setUp() throws Exception
	{
	}

	@AfterMethod
	public void tearDown() throws Exception
	{
	}

	@Test
	public void testHash() throws NoSuchAlgorithmException
	{
		final Charset charset = Charset.forName("UTF-8");
		final String password = "abcdefghijklmnopqrst";
		final String newInsertPassword = "abcdefghijklmnopqrst";
		final String salt = new String(Hasher.getRandomSalt(8, charset), charset);
		final HashAlgorithm hashAlgorithm = HashAlgorithm.SHA_512;
		final String expected = Hasher.hash(password, salt, hashAlgorithm, charset);
		final String actual = Hasher.hash(newInsertPassword, salt, hashAlgorithm, charset);

		AssertJUnit
			.assertTrue("'expected' should be equal with 'actual'.", expected.equals(actual));
	}

	@Test
	public void testHashAndBase64() throws NoSuchAlgorithmException
	{
		final Charset charset = Charset.forName("UTF-8");
		final String password = "secret";
		final String newInsertPassword = "secret";
		final String salt = new String(Hasher.getRandomSalt(8, charset), charset);
		final HashAlgorithm hashAlgorithm = HashAlgorithm.SHA_512;
		final String expected = Hasher.hashAndBase64(password, salt, hashAlgorithm, charset);
		final String actual = Hasher.hashAndBase64(newInsertPassword, salt, hashAlgorithm, charset);
		AssertJUnit
			.assertTrue("'expected' should be equal with 'actual'.", expected.equals(actual));
	}

	@Test
	public void testHashAndHex() throws NoSuchAlgorithmException, InvalidKeyException,
		UnsupportedEncodingException, NoSuchPaddingException, IllegalBlockSizeException,
		BadPaddingException
	{
		final Charset charset = Charset.forName("UTF-8");
		final String password = "xxx";
		final String newInsertPassword = "xxx";
		final String salt = new String(Hasher.getRandomSalt(8, charset), charset);
		final HashAlgorithm hashAlgorithm = HashAlgorithm.SHA_512;
		final String expected = Hasher.hashAndHex(password, salt, hashAlgorithm, charset);
		final String actual = Hasher.hashAndHex(newInsertPassword, salt, hashAlgorithm, charset);
		System.out.println(salt);
		System.out.println(expected);
		System.out.println(actual);
		AssertJUnit
			.assertTrue("'expected' should be equal with 'actual'.", expected.equals(actual));
	}

}
