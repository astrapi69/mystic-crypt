/**
 * The MIT License
 *
 * Copyright (C) 2015 Asterios Raptis
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
 * associated documentation files (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge, publish, distribute,
 * sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or
 * substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
 * NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package de.alpharogroup.crypto.model;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

import javax.crypto.Cipher;

import org.testng.annotations.Test;

import de.alpharogroup.crypto.CryptConst;
import de.alpharogroup.crypto.algorithm.SunJCEAlgorithm;
import de.alpharogroup.evaluate.object.evaluators.EqualsHashCodeAndToStringEvaluator;

/**
 * The unit test class for the class {@link CryptModel}
 */
public class CryptModelTest
{

	/**
	 * Test method for {@link CryptModel} constructors and builders
	 */
	@Test
	public final void testConstructors()
	{
		String privateKey = "D1D15ED36B887AF1";
		CryptModel<Cipher, String> model = CryptModel.<Cipher, String> builder().key(privateKey)
			.algorithm(SunJCEAlgorithm.PBEWithMD5AndDES).salt(CryptConst.SALT).iterationCount(19)
			.operationMode(Cipher.ENCRYPT_MODE).build();
		assertNotNull(model);
		model = CryptModel.<Cipher, String> builder().build();
		assertNotNull(model);
		model = new CryptModel<>();
		model.setKey(privateKey);
		model.setAlgorithm(SunJCEAlgorithm.PBEWithMD5AndDES);
		model.setSalt(CryptConst.SALT);
		model.setIterationCount(19);
		model.setOperationMode(Cipher.ENCRYPT_MODE);
	}

	/**
	 * Test method for {@link CryptModel#equals(Object)} , {@link CryptModel#hashCode()} and
	 * {@link CryptModel#toString()}
	 */
	@Test
	public void testEqualsHashcodeAndToStringWithClass()
	{
		final boolean expected;
		final boolean actual;

		String privateKey = "D1D15ED36B887AF1";
		CryptModel<Cipher, String> first = CryptModel.<Cipher, String> builder().key(privateKey)
			.algorithm(SunJCEAlgorithm.PBEWithMD5AndDES).salt(CryptConst.SALT).iterationCount(19)
			.operationMode(Cipher.ENCRYPT_MODE).build();
		CryptModel<Cipher, String> second = CryptModel.<Cipher, String> builder().build();
		CryptModel<Cipher, String> third = CryptModel.<Cipher, String> builder().key(privateKey)
			.algorithm(SunJCEAlgorithm.PBEWithMD5AndDES).salt(CryptConst.SALT).iterationCount(19)
			.operationMode(Cipher.ENCRYPT_MODE).build();
		CryptModel<Cipher, String> fourth = CryptModel.<Cipher, String> builder().key(privateKey)
			.algorithm(SunJCEAlgorithm.PBEWithMD5AndDES).salt(CryptConst.SALT).iterationCount(19)
			.operationMode(Cipher.ENCRYPT_MODE).build();

		actual = EqualsHashCodeAndToStringEvaluator.evaluateEqualsHashcodeAndToString(first, second,
			third, fourth);
		expected = true;
		assertEquals(expected, actual);
	}

}
