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
package io.github.astrapi69.mystic.crypt.core;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import org.junit.jupiter.api.Test;

import io.github.astrapi69.crypt.api.algorithm.SunJCEAlgorithm;
import io.github.astrapi69.crypt.api.algorithm.compound.CompoundAlgorithm;
import io.github.astrapi69.crypt.data.factory.CipherFactory;
import io.github.astrapi69.crypt.data.model.CryptModel;

/**
 * Test class for the factory methods {@link AbstractCryptor#newSalt()},
 * {@link AbstractCryptor#newIterationCount()} and {@link AbstractCryptor#newAlgorithm()}
 */
public class AbstractCryptorTest
{

	@Test
	public void newSalt_whenModelHasNoSalt_generatesRandomSaltAndWritesBackToModel()
		throws Exception
	{
		CryptModel<Cipher, String, String> model = CryptModel.<Cipher, String, String> builder()
			.key("test-password").build();
		assertNull(model.getSalt());

		new TestPbeCryptor(model);

		assertNotNull(model.getSalt());
		assertEquals(AbstractCryptor.DEFAULT_SALT_LENGTH, model.getSalt().length);
	}

	@Test
	public void newSalt_whenModelHasExplicitSalt_reusesItUnchanged() throws Exception
	{
		byte[] explicitSalt = { 1, 2, 3, 4, 5, 6, 7, 8 };
		CryptModel<Cipher, String, String> model = CryptModel.<Cipher, String, String> builder()
			.key("test-password").salt(explicitSalt).build();

		new TestPbeCryptor(model);

		assertArrayEquals(explicitSalt, model.getSalt());
	}

	@Test
	public void newSalt_twoModelsWithoutExplicitSalt_produceDifferentRandomSalts() throws Exception
	{
		CryptModel<Cipher, String, String> firstModel = CryptModel
			.<Cipher, String, String> builder().key("test-password").build();
		CryptModel<Cipher, String, String> secondModel = CryptModel
			.<Cipher, String, String> builder().key("test-password").build();

		new TestPbeCryptor(firstModel);
		new TestPbeCryptor(secondModel);

		assertFalse(Arrays.equals(firstModel.getSalt(), secondModel.getSalt()));
	}

	@Test
	public void newIterationCount_whenModelHasNoIterationCount_usesSecureDefault() throws Exception
	{
		CryptModel<Cipher, String, String> model = CryptModel.<Cipher, String, String> builder()
			.key("test-password").build();
		assertNull(model.getIterationCount());

		TestPbeCryptor cryptor = new TestPbeCryptor(model);

		assertEquals(AbstractCryptor.DEFAULT_ITERATION_COUNT, cryptor.newIterationCount());
	}

	@Test
	public void newIterationCount_whenModelHasExplicitIterationCount_usesIt() throws Exception
	{
		CryptModel<Cipher, String, String> model = CryptModel.<Cipher, String, String> builder()
			.key("test-password").iterationCount(4242).build();

		TestPbeCryptor cryptor = new TestPbeCryptor(model);

		assertEquals(4242, cryptor.newIterationCount());
	}

	@Test
	public void newAlgorithm_whenModelHasNoAlgorithm_usesBcPbeDefault() throws Exception
	{
		CryptModel<Cipher, String, String> model = CryptModel.<Cipher, String, String> builder()
			.key("test-password").build();
		assertNull(model.getAlgorithm());

		TestPbeCryptor cryptor = new TestPbeCryptor(model);

		assertEquals(CompoundAlgorithm.PBE_WITH_SHA1_AND_128BIT_AES_CBC_BC.getAlgorithm(),
			cryptor.newAlgorithm());
	}

	@Test
	public void newAlgorithm_whenModelHasExplicitAlgorithm_usesIt() throws Exception
	{
		CryptModel<Cipher, String, String> model = CryptModel.<Cipher, String, String> builder()
			.key("test-password").salt(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 })
			.algorithm(SunJCEAlgorithm.PBEWithMD5AndDES).build();

		TestPbeCryptor cryptor = new TestPbeCryptor(model);

		assertEquals(SunJCEAlgorithm.PBEWithMD5AndDES.getAlgorithm(), cryptor.newAlgorithm());
	}

	@Test
	public void bcProvider_isRegisteredAfterConstruction_andRegistrationIsIdempotent()
		throws Exception
	{
		new TestPbeCryptor(
			CryptModel.<Cipher, String, String> builder().key("test-password").build());
		assertNotNull(Security.getProvider("BC"));

		// constructing a second instance must not throw even though the provider is already
		// registered
		new TestPbeCryptor(
			CryptModel.<Cipher, String, String> builder().key("test-password").build());
	}

	@Test
	public void keyOnlyConstructor_buildsAModelWithThatKeyAndInitializesIt() throws Exception
	{
		TestPbeCryptor cryptor = new TestPbeCryptor("test-password");

		assertEquals("test-password", cryptor.getModel().getKey());
		assertNotNull(cryptor.getModel().getCipher());
		assertNotNull(cryptor.getModel().getSalt());
	}

	@Test
	public void newAlgorithmParameterSpec_answersThePbeParameterSpecWithSaltAndIterationCount()
		throws Exception
	{
		byte[] salt = { 1, 2, 3, 4, 5, 6, 7, 8 };
		TestPbeCryptor cryptor = new TestPbeCryptor(
			CryptModel.<Cipher, String, String> builder().key("test-password").build());

		AlgorithmParameterSpec parameterSpec = cryptor.newAlgorithmParameterSpec(salt, 4711);

		assertInstanceOf(PBEParameterSpec.class, parameterSpec);
		assertArrayEquals(salt, ((PBEParameterSpec)parameterSpec).getSalt());
		assertEquals(4711, ((PBEParameterSpec)parameterSpec).getIterationCount());
	}

	@Test
	public void newKeySpec_answersThePbeKeySpecWithPasswordSaltAndIterationCount() throws Exception
	{
		byte[] salt = { 1, 2, 3, 4, 5, 6, 7, 8 };
		TestPbeCryptor cryptor = new TestPbeCryptor(
			CryptModel.<Cipher, String, String> builder().key("test-password").build());

		KeySpec keySpec = cryptor.newKeySpec("test-password", salt, 4711);

		assertInstanceOf(PBEKeySpec.class, keySpec);
		assertArrayEquals("test-password".toCharArray(), ((PBEKeySpec)keySpec).getPassword());
		assertArrayEquals(salt, ((PBEKeySpec)keySpec).getSalt());
		assertEquals(4711, ((PBEKeySpec)keySpec).getIterationCount());
	}

	@Test
	public void newCipher_withSecretKeyAndParameterSpec_producesAWorkingCipherPair()
		throws Exception
	{
		byte[] salt = { 1, 2, 3, 4, 5, 6, 7, 8 };
		int iterationCount = 1024;
		String algorithm = CompoundAlgorithm.PBE_WITH_SHA1_AND_128BIT_AES_CBC_BC.getAlgorithm();
		TestPbeCryptor cryptor = new TestPbeCryptor(
			CryptModel.<Cipher, String, String> builder().key("test-password").build());

		SecretKey secretKey = cryptor.newSecretKeyFactory(algorithm)
			.generateSecret(cryptor.newKeySpec("test-password", salt, iterationCount));
		AlgorithmParameterSpec parameterSpec = cryptor.newAlgorithmParameterSpec(salt,
			iterationCount);

		Cipher encryptCipher = cryptor.newCipher(Cipher.ENCRYPT_MODE, secretKey, parameterSpec,
			algorithm);
		Cipher decryptCipher = cryptor.newCipher(Cipher.DECRYPT_MODE, secretKey, parameterSpec,
			algorithm);

		assertEquals(algorithm, encryptCipher.getAlgorithm());
		byte[] plain = "the quick brown fox".getBytes(StandardCharsets.UTF_8);
		byte[] encrypted = encryptCipher.doFinal(plain);
		assertFalse(Arrays.equals(plain, encrypted));
		assertArrayEquals(plain, decryptCipher.doFinal(encrypted));
	}

	/**
	 * Minimal concrete {@link AbstractCryptor} subclass used only to exercise the protected
	 * factory-method defaults under test. Builds a real PBE {@link Cipher} so construction also
	 * proves the generated salt/iterationCount/algorithm combination actually works end-to-end.
	 */
	private static class TestPbeCryptor extends AbstractCryptor<Cipher, String, String>
	{
		private static final long serialVersionUID = 1L;

		TestPbeCryptor(final CryptModel<Cipher, String, String> model) throws Exception
		{
			super(model);
		}

		TestPbeCryptor(final String key) throws Exception
		{
			super(key);
		}

		@Override
		public int newOperationMode()
		{
			return Cipher.ENCRYPT_MODE;
		}

		@Override
		protected Cipher newCipher(final String key, final String algorithm, final byte[] salt,
			final int iterationCount, final int operationMode)
			throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
			InvalidKeyException, InvalidAlgorithmParameterException
		{
			return CipherFactory.newPBECipher(key.toCharArray(), operationMode, algorithm, salt,
				iterationCount);
		}
	}
}
