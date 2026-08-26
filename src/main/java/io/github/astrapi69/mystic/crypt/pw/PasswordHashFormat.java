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
package io.github.astrapi69.mystic.crypt.pw;

/**
 * The password hash encodings this library produces, and how to tell which one a stored hash is.
 * <p>
 * Every one of them writes what it is into the hash itself, so the algorithm never has to be
 * supplied a second time when verifying. Asking for it again only creates a way to get it wrong:
 * naming the wrong algorithm turns "this is a bcrypt hash" into "the password does not match",
 * which sends the reader after the password instead of after the mismatch.
 */
public enum PasswordHashFormat
{

	/** Argon2id, encoded in the standard PHC format as {@code $argon2id$...}. */
	ARGON2ID("$argon2id$"),

	/** PBKDF2-HMAC-SHA256, encoded as {@code $pbkdf2-sha256$...}. */
	PBKDF2("$pbkdf2-sha256$"),

	/** scrypt, encoded as {@code $scrypt$...}. */
	SCRYPT(ScryptSupport.PREFIX),

	/**
	 * bcrypt, encoded in its own modular crypt format. All three of the {@code 2a}, {@code 2b} and
	 * {@code 2y} revisions are the same construction with different revision letters, and hashes of
	 * all three are found in the wild, so all three are recognised.
	 */
	BCRYPT("$2a$", "$2b$", "$2y$");

	private final String[] prefixes;

	PasswordHashFormat(final String... prefixes)
	{
		this.prefixes = prefixes;
	}

	/**
	 * Reads from an encoded hash which algorithm produced it.
	 *
	 * @param encodedHash
	 *            the encoded hash
	 * @return the format the hash is in
	 * @throws IllegalArgumentException
	 *             if the encoding belongs to none of these formats
	 */
	public static PasswordHashFormat of(final String encodedHash)
	{
		if (encodedHash != null)
		{
			for (final PasswordHashFormat format : values())
			{
				if (format.matches(encodedHash))
				{
					return format;
				}
			}
		}
		throw new IllegalArgumentException("'" + encodedHash
			+ "' is not an encoded hash of a known algorithm: it starts with none of $argon2id$, "
			+ "$pbkdf2-sha256$, $scrypt$, $2a$, $2b$ or $2y$");
	}

	private boolean matches(final String encodedHash)
	{
		for (final String prefix : prefixes)
		{
			if (encodedHash.startsWith(prefix))
			{
				return true;
			}
		}
		return false;
	}
}
