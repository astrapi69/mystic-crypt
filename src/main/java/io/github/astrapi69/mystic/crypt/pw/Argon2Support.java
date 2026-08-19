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
package io.github.astrapi69.mystic.crypt.pw;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import io.github.astrapi69.random.number.RandomByteFactory;

/**
 * Package-private helper for Argon2id password hashing, encoded in the standard PHC string format
 * ({@code $argon2id$v=19$m=<memoryKB>,t=<iterations>,p=<parallelism>$<salt>$<hash>}) so the
 * parameters travel with the hash - a hash produced with one set of parameters can still be
 * verified even if the defaults below change later.
 * <p>
 * Both {@link #hash(char[])} and {@link #verify(char[], String)} zero the given {@code password}
 * array before returning (success, failure, or exception) - callers must not reuse the array
 * afterwards.
 */
final class Argon2Support
{

	/** Salt length in bytes. */
	static final int SALT_LENGTH = 16;

	/** Output hash length in bytes. */
	static final int HASH_LENGTH = 32;

	/** Default number of iterations (time cost). */
	static final int DEFAULT_ITERATIONS = 3;

	/** Default memory cost in KB (64 MB). Tune per the OWASP Password Storage Cheat Sheet. */
	static final int DEFAULT_MEMORY_KB = 65536;

	/** Default degree of parallelism. */
	static final int DEFAULT_PARALLELISM = 1;

	private static final String PREFIX = "$argon2id$v=" + Argon2Parameters.ARGON2_VERSION_13;

	private Argon2Support()
	{
	}

	/**
	 * Hashes the given password with a fresh random salt and the default parameters, encoded as a
	 * PHC-format string.
	 *
	 * @param password
	 *            the password
	 * @return the encoded hash
	 */
	static String hash(final char[] password)
	{
		Objects.requireNonNull(password);
		try
		{
			final byte[] salt = RandomByteFactory.randomByteArray(SALT_LENGTH);
			final byte[] hash = rawHash(password, salt, DEFAULT_ITERATIONS, DEFAULT_MEMORY_KB,
				DEFAULT_PARALLELISM);
			return encode(salt, hash, DEFAULT_ITERATIONS, DEFAULT_MEMORY_KB, DEFAULT_PARALLELISM);
		}
		finally
		{
			Arrays.fill(password, '\0');
		}
	}

	/**
	 * Verifies the given password against a previously encoded PHC-format hash.
	 *
	 * @param password
	 *            the password to check
	 * @param encoded
	 *            the previously encoded hash, as produced by {@link #hash(char[])}
	 * @return true if the password matches, false if it does not match or {@code encoded} is
	 *         malformed
	 */
	static boolean verify(final char[] password, final String encoded)
	{
		Objects.requireNonNull(password);
		Objects.requireNonNull(encoded);
		try
		{
			final Decoded decoded;
			try
			{
				decoded = decode(encoded);
			}
			catch (final RuntimeException malformed)
			{
				return false;
			}
			final byte[] actualHash = rawHash(password, decoded.salt, decoded.iterations,
				decoded.memoryKB, decoded.parallelism);
			return MessageDigest.isEqual(decoded.hash, actualHash);
		}
		finally
		{
			Arrays.fill(password, '\0');
		}
	}

	private static byte[] rawHash(final char[] password, final byte[] salt, final int iterations,
		final int memoryKB, final int parallelism)
	{
		final Argon2Parameters parameters = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
			.withVersion(Argon2Parameters.ARGON2_VERSION_13).withIterations(iterations)
			.withMemoryAsKB(memoryKB).withParallelism(parallelism).withSalt(salt).build();
		final Argon2BytesGenerator generator = new Argon2BytesGenerator();
		generator.init(parameters);
		final byte[] hash = new byte[HASH_LENGTH];
		generator.generateBytes(password, hash);
		return hash;
	}

	private static String encode(final byte[] salt, final byte[] hash, final int iterations,
		final int memoryKB, final int parallelism)
	{
		final Base64.Encoder encoder = Base64.getEncoder().withoutPadding();
		return PREFIX + "$m=" + memoryKB + ",t=" + iterations + ",p=" + parallelism + "$"
			+ encoder.encodeToString(salt) + "$" + encoder.encodeToString(hash);
	}

	private static Decoded decode(final String encoded)
	{
		final String[] parts = encoded.split("\\$");
		// parts[0] is empty (string starts with '$'); parts[1]="argon2id"; parts[2]="v=19";
		// parts[3]="m=...,t=...,p=..."; parts[4]=salt; parts[5]=hash
		if (parts.length != 6 || !"argon2id".equals(parts[1]))
		{
			throw new IllegalArgumentException("not a valid argon2id PHC-encoded hash");
		}
		final String[] params = parts[3].split(",");
		int memoryKB = -1;
		int iterations = -1;
		int parallelism = -1;
		for (final String param : params)
		{
			final String[] keyValue = param.split("=");
			if (keyValue.length != 2)
			{
				throw new IllegalArgumentException("not a valid argon2id PHC-encoded hash");
			}
			switch (keyValue[0])
			{
				case "m" :
					memoryKB = Integer.parseInt(keyValue[1]);
					break;
				case "t" :
					iterations = Integer.parseInt(keyValue[1]);
					break;
				case "p" :
					parallelism = Integer.parseInt(keyValue[1]);
					break;
				default :
					throw new IllegalArgumentException("not a valid argon2id PHC-encoded hash");
			}
		}
		if (memoryKB < 0 || iterations < 0 || parallelism < 0)
		{
			throw new IllegalArgumentException("not a valid argon2id PHC-encoded hash");
		}
		final byte[] salt = Base64.getDecoder().decode(parts[4]);
		final byte[] hash = Base64.getDecoder().decode(parts[5]);
		return new Decoded(salt, hash, iterations, memoryKB, parallelism);
	}

	private static final class Decoded
	{
		private final byte[] salt;
		private final byte[] hash;
		private final int iterations;
		private final int memoryKB;
		private final int parallelism;

		private Decoded(final byte[] salt, final byte[] hash, final int iterations,
			final int memoryKB, final int parallelism)
		{
			this.salt = salt;
			this.hash = hash;
			this.iterations = iterations;
			this.memoryKB = memoryKB;
			this.parallelism = parallelism;
		}
	}

}
