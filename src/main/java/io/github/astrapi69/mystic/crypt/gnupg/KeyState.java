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

import java.time.Instant;

/**
 * One key of an OpenPGP certificate, primary key or subkey, as a GnuPG home holds it. Public facts
 * only: nothing secret is read to build it
 *
 * @param fingerprint
 *            the fingerprint, upper case hex without spaces
 * @param primary
 *            whether this is the primary key
 * @param algorithm
 *            the algorithm in the words gpg uses, for example {@code rsa4096} or {@code ed25519}
 * @param usage
 *            what the key is for, in gpg's letters and order: S sign, C certify, E encrypt, A
 *            authenticate - {@code SC} for a primary key that signs and certifies
 * @param created
 *            when it was created
 * @param expires
 *            when it expires, null when it does not
 * @param secret
 *            whether the home holds its secret part
 */
public record KeyState(String fingerprint, boolean primary, String algorithm, String usage,
	Instant created, Instant expires, SecretPart secret) {
}
