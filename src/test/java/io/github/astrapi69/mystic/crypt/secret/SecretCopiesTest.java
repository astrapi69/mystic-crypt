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
package io.github.astrapi69.mystic.crypt.secret;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.interfaces.EdECPrivateKey;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.spec.PBEKeySpec;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import io.github.astrapi69.mystic.crypt.key.Ed25519ExpandedPrivateKey;
import io.github.astrapi69.mystic.crypt.key.SeedDerivation;
import io.github.astrapi69.mystic.crypt.pw.PassphraseCryptor;
import io.github.astrapi69.mystic.crypt.pw.PassphraseEnvelope;

/**
 * Every copy of secret material a method makes on its way is held by a {@link SecretCopies} and
 * overwritten when the method is done. A copy that is never handed out cannot be read by a test
 * through the method's result, so the copies themselves are shown to a watcher after the wipe, and
 * each test reads every copy it was shown (#227). A missing wipe leaves a secret in memory longer:
 * that is a change of behaviour, not an equivalent mutant.
 */
class SecretCopiesTest
{

	private final List<Object> shown = new ArrayList<>();

	@BeforeEach
	void watch()
	{
		SecretCopies.WATCHER.set(shown::add);
	}

	@AfterEach
	void stopWatching()
	{
		SecretCopies.WATCHER.remove();
	}

	@Test
	@DisplayName("every kind of copy is overwritten on close, and shown to the watcher afterwards")
	void everyKindOfCopy_isOverwritten_onClose()
	{
		byte[] bytes = "key bytes".getBytes(StandardCharsets.UTF_8);
		char[] chars = "passphrase".toCharArray();
		byte[] behindBytes = "encoded".getBytes(StandardCharsets.UTF_8);
		char[] behindChars = "decoded".toCharArray();
		PBEKeySpec spec = new PBEKeySpec("passphrase".toCharArray(), new byte[16], 1, 256);

		try (SecretCopies copies = SecretCopies.open())
		{
			assertSame(bytes, copies.hold(bytes), "holding hands the copy back to be used");
			assertSame(chars, copies.hold(chars));
			copies.hold(ByteBuffer.wrap(behindBytes));
			copies.hold(CharBuffer.wrap(behindChars));
			assertSame(spec, copies.hold(spec));
		}

		assertArrayEquals(new byte[bytes.length], bytes);
		assertArrayEquals(new char[chars.length], chars);
		assertArrayEquals(new byte[behindBytes.length], behindBytes);
		assertArrayEquals(new char[behindChars.length], behindChars);
		assertThrows(IllegalStateException.class, spec::getPassword,
			"a cleared PBEKeySpec refuses to hand out its password");
		assertEquals(5, shown.size(), "the watcher sees every copy");
	}

	@Test
	@DisplayName("null is handed back and nothing is held for it")
	void null_isHandedBack_andNothingIsHeld()
	{
		try (SecretCopies copies = SecretCopies.open())
		{
			assertNull(copies.hold((byte[])null));
			assertNull(copies.hold((char[])null));
			assertNull(copies.hold((ByteBuffer)null));
			assertNull(copies.hold((CharBuffer)null));
			assertNull(copies.hold((PBEKeySpec)null));
		}

		assertTrue(shown.isEmpty(), "nothing to overwrite and nothing to show: " + shown);
	}

	@Test
	@DisplayName("deriving a key from a String leaves no copy of the passphrase or the key behind")
	void deriveKey_fromAString_leavesEveryCopyOverwritten() throws Exception
	{
		PassphraseEnvelope.deriveKey("correct horse battery staple", new byte[16], 1_000);

		assertEveryCopyIsOverwritten();
		assertTrue(countOf(char[].class) >= 1, "the characters of the passphrase: " + shown);
		assertTrue(countOf(PBEKeySpec.class) >= 1, "the key spec's copy of the passphrase");
		assertTrue(countOf(byte[].class) >= 2, "the derived key bytes of both overloads: " + shown);
	}

	@Test
	@DisplayName("encoding to UTF-8 leaves no copy in the encoder's buffer")
	void toUtf8_leavesTheEncodersBufferOverwritten()
	{
		SecretBuffers.toUtf8("a passphrase with ümlauts".toCharArray());

		assertEveryCopyIsOverwritten();
		assertEquals(1, countOf(ByteBuffer.class), "the encoder's buffer: " + shown);
	}

	@Test
	@DisplayName("decoding from UTF-8 leaves no copy in the decoder's buffer")
	void fromUtf8_leavesTheDecodersBufferOverwritten()
	{
		SecretBuffers.fromUtf8("a passphrase with ümlauts".getBytes(StandardCharsets.UTF_8));

		assertEveryCopyIsOverwritten();
		assertEquals(1, countOf(CharBuffer.class), "the decoder's buffer: " + shown);
	}

	@Test
	@DisplayName("expanding an Ed25519 key leaves neither its hash nor its clamped scalar behind")
	void expandingAnEd25519Key_leavesTheHashAndTheScalarOverwritten() throws Exception
	{
		EdECPrivateKey privateKey = (EdECPrivateKey)KeyPairGenerator.getInstance("Ed25519")
			.generateKeyPair().getPrivate();

		Ed25519ExpandedPrivateKey.of(privateKey);

		assertEveryCopyIsOverwritten();
		assertTrue(
			shown.stream().anyMatch(copy -> copy instanceof byte[] bytes && bytes.length == 64),
			"the SHA-512 of the seed: " + shown);
		assertTrue(
			shown.stream().anyMatch(copy -> copy instanceof byte[] bytes && bytes.length == 32),
			"the clamped scalar: " + shown);
	}

	@Test
	@DisplayName("deriving a key pair from a seed leaves the private key bytes overwritten")
	void deriningAKeyPairFromASeed_leavesThePrivateKeyBytesOverwritten()
	{
		SeedDerivation.keyPairOf(SeedDerivation.Curve.ED25519, new byte[32], 44, 0, 0);

		assertEveryCopyIsOverwritten();
		assertEquals(1, countOf(byte[].class), "the derived private key bytes: " + shown);
	}

	@Test
	@DisplayName("sealing with PassphraseCryptor leaves the derived key bytes overwritten")
	void passphraseCryptor_leavesTheDerivedKeyBytesOverwritten()
	{
		PassphraseCryptor.encrypt("pass".toCharArray(), "plain".getBytes(StandardCharsets.UTF_8));

		assertEveryCopyIsOverwritten();
		assertTrue(
			shown.stream().anyMatch(copy -> copy instanceof byte[] bytes && bytes.length == 32),
			"the derived key bytes: " + shown);
	}

	private void assertEveryCopyIsOverwritten()
	{
		assertTrue(!shown.isEmpty(), "the method has to have held its copies");
		for (Object copy : shown)
		{
			switch (copy)
			{
				case byte[] bytes -> assertArrayEquals(new byte[bytes.length], bytes);
				case char[] chars -> assertArrayEquals(new char[chars.length], chars);
				case ByteBuffer buffer -> assertArrayEquals(new byte[buffer.array().length],
					buffer.array());
				case CharBuffer buffer -> assertArrayEquals(new char[buffer.array().length],
					buffer.array());
				case PBEKeySpec spec -> assertThrows(IllegalStateException.class, spec::getPassword);
				default -> throw new AssertionError("a copy of an unexpected kind: " + copy);
			}
		}
	}

	private long countOf(final Class<?> kind)
	{
		return shown.stream().filter(kind::isInstance).count();
	}
}
