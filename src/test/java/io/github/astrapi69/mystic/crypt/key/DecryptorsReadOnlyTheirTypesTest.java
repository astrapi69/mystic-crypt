/*
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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serial;
import java.io.Serializable;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.Cipher;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import io.github.astrapi69.crypt.api.algorithm.SunJCEAlgorithm;
import io.github.astrapi69.crypt.data.model.CryptModel;
import io.github.astrapi69.mystic.crypt.file.GenericObjectDecryptor;
import io.github.astrapi69.mystic.crypt.file.GenericObjectEncryptor;
import io.github.astrapi69.test.object.Person;
import io.github.astrapi69.test.object.enumeration.Gender;

/**
 * The decryptors read back only the types they are meant to read: the hybrid envelope only its own
 * model and byte arrays, the generic decryptors only what their caller names. Every crafted input
 * here is harmless: a type that notes whether it was built, and a nesting of empty lists.
 */
class DecryptorsReadOnlyTheirTypesTest
{

	/** Set when an instance of {@link Tripwire} is read back; it must never be */
	static volatile boolean tripped;

	/** A type no decryptor here is meant to read, which notes that it was built */
	static class Tripwire implements Serializable
	{
		@Serial
		private static final long serialVersionUID = 1L;

		@Serial
		private void readObject(final ObjectInputStream in)
			throws IOException, ClassNotFoundException
		{
			in.defaultReadObject();
			tripped = true;
		}
	}

	private static KeyPair keyPair;

	@TempDir
	File directory;

	@BeforeAll
	static void generateAKeyPair() throws Exception
	{
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(2048);
		keyPair = generator.generateKeyPair();
	}

	private static byte[] serialized(final Object object) throws IOException
	{
		ByteArrayOutputStream bytes = new ByteArrayOutputStream();
		try (ObjectOutputStream out = new ObjectOutputStream(bytes))
		{
			out.writeObject(object);
		}
		return bytes.toByteArray();
	}

	@Test
	@DisplayName("an envelope that holds a foreign type is refused before the type is built")
	void privateKeyDecryptor_aForeignTypeInTheEnvelope_isRefused() throws Exception
	{
		tripped = false;
		byte[] crafted = serialized(new Tripwire());

		assertThrows(InvalidClassException.class,
			() -> new PrivateKeyDecryptor(keyPair.getPrivate()).decrypt(crafted));

		assertFalse(tripped, "the foreign type was built");
	}

	@Test
	@DisplayName("an envelope that holds a deep nesting of empty lists is refused")
	void privateKeyDecryptor_aNestingInTheEnvelope_isRefused() throws Exception
	{
		ArrayList<Object> nesting = new ArrayList<>();
		ArrayList<Object> current = nesting;
		for (int level = 0; level < 100; level++)
		{
			ArrayList<Object> next = new ArrayList<>();
			current.add(next);
			current = next;
		}
		byte[] crafted = serialized(nesting);

		assertThrows(InvalidClassException.class,
			() -> new PrivateKeyDecryptor(keyPair.getPrivate()).decrypt(crafted));
	}

	@Test
	@DisplayName("the generic decryptor reads a string by default, and nothing else")
	void privateKeyGenericDecryptor_byDefault_readsOnlyAString() throws Exception
	{
		PublicKeyGenericEncryptor<Serializable> encryptor = new PublicKeyGenericEncryptor<>(
			keyPair.getPublic());
		PrivateKeyGenericDecryptor<Serializable> decryptor = new PrivateKeyGenericDecryptor<>(
			keyPair.getPrivate());

		assertEquals("a string", decryptor.decrypt(encryptor.encrypt("a string")));
		byte[] person = encryptor.encrypt(Person.builder().name("Foo").gender(Gender.MALE).build());
		assertThrows(InvalidClassException.class, () -> decryptor.decrypt(person));
		tripped = false;
		byte[] tripwire = encryptor.encrypt(new Tripwire());
		assertThrows(InvalidClassException.class, () -> decryptor.decrypt(tripwire));
		assertFalse(tripped, "the foreign type was built");
	}

	@Test
	@DisplayName("the generic decryptor reads the types its caller names")
	void privateKeyGenericDecryptor_withNamedTypes_readsThem() throws Exception
	{
		Person person = Person.builder().name("Foo").gender(Gender.MALE).married(true).build();
		byte[] encrypted = new PublicKeyGenericEncryptor<Person>(keyPair.getPublic())
			.encrypt(person);

		PrivateKeyGenericDecryptor<Person> decryptor = new PrivateKeyGenericDecryptor<>(
			keyPair.getPrivate(), List.of(Person.class, Gender.class, Enum.class, Boolean.class));

		assertEquals(person, decryptor.decrypt(encrypted));
	}

	@Test
	@DisplayName("the file decryptor reads a string by default, and refuses what its caller did not name")
	void genericObjectDecryptor_byDefault_refusesAnUnnamedType() throws Exception
	{
		CryptModel<Cipher, String, String> model = CryptModel.<Cipher, String, String> builder()
			.key("D1D15ED36B887AF1").algorithm(SunJCEAlgorithm.PBEWithMD5AndDES).build();
		File encrypted = new GenericObjectEncryptor<Person, String>(model,
			new File(directory, "person.enc"))
				.encrypt(Person.builder().name("Foo").gender(Gender.MALE).build());

		assertThrows(InvalidClassException.class,
			() -> new GenericObjectDecryptor<Person, String>(model).decrypt(encrypted));
	}
}
