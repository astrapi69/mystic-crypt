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
package io.github.astrapi69.mystic.crypt.gnupg;

import java.util.List;

/**
 * One OpenPGP certificate of a GnuPG home: its primary key, its subkeys and whether gpg keeps a
 * revocation certificate for it
 *
 * @param fingerprint
 *            the primary key's fingerprint, upper case hex without spaces
 * @param userId
 *            the first user ID, empty when the certificate has none
 * @param keys
 *            the primary key first, then the subkeys in the order the keyring holds them
 * @param revocationCertificate
 *            what {@code openpgp-revocs.d} holds for the primary key
 */
public record KeyRingState(String fingerprint, String userId, List<KeyState> keys,
	RevocationCertificate revocationCertificate) {

	/**
	 * Copies the list, so a state read once cannot change afterwards
	 */
	public KeyRingState {
		keys = List.copyOf(keys);
	}
}
