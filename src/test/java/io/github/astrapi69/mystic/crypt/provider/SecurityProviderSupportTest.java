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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.Provider;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

/**
 * The unit test class for {@link SecurityProviderSupport}. It exercises both arms of the "register
 * the provider if absent" guard that every static initializer in this library shares: once with
 * Bouncy Castle removed (it must register and answer {@code true}) and once with Bouncy Castle
 * present (it must be a no-op and answer {@code false}). The provider is always restored in a
 * {@code finally} block so no other test observes a missing provider.
 */
public class SecurityProviderSupportTest
{

	/**
	 * Test method for {@link SecurityProviderSupport#ensureBouncyCastle()}
	 */
	@Test
	public void ensureBouncyCastle_registersWhenAbsentAndIsNoOpWhenPresent()
	{
		final Provider existing = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
		try
		{
			Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
			assertNull(Security.getProvider(BouncyCastleProvider.PROVIDER_NAME),
				"the provider must be absent for the first part of this test");

			assertTrue(SecurityProviderSupport.ensureBouncyCastle(),
				"a call with the provider absent must register it and answer true");
			assertNotNull(Security.getProvider(BouncyCastleProvider.PROVIDER_NAME),
				"the provider must be registered after the first call");

			assertFalse(SecurityProviderSupport.ensureBouncyCastle(),
				"a call with the provider present must be a no-op and answer false");
			assertNotNull(Security.getProvider(BouncyCastleProvider.PROVIDER_NAME),
				"the provider must still be registered after the second call");
		}
		finally
		{
			// restore the exact state other tests rely on
			if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null
				&& existing != null)
			{
				Security.addProvider(existing);
			}
		}
	}
}
