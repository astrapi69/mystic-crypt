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
package io.github.astrapi69.mystic.crypt.provider;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * The class {@link SecurityProviderSupport} centralizes the registration of the Bouncy Castle
 * {@link java.security.Provider}. Many classes in this library register Bouncy Castle from their
 * own static initializer with the same idempotent guard; extracting it into one place keeps that
 * guard testable (the first class that loads registers the provider, so the "already present" arm
 * could never be reached in place) and avoids duplicating the logic.
 */
public final class SecurityProviderSupport
{

	private SecurityProviderSupport()
	{
	}

	/**
	 * Ensures the Bouncy Castle security {@link java.security.Provider} is registered. If it is not
	 * yet registered it is added, otherwise this method is a no-op. The method is idempotent and
	 * safe to call from any number of static initializers.
	 *
	 * @return {@code true} if this call registered the provider, {@code false} if it was already
	 *         present
	 */
	public static boolean ensureBouncyCastle()
	{
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
		{
			Security.addProvider(new BouncyCastleProvider());
			return true;
		}
		return false;
	}
}
