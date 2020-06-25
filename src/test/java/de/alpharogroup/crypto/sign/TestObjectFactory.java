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
package de.alpharogroup.crypto.sign;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.time.LocalDate;
import java.time.Month;
import java.time.ZoneId;
import java.util.Date;

import de.alpharogroup.crypto.factories.CertFactory;
import de.alpharogroup.random.RandomExtensions;

public final class TestObjectFactory {
	public static Certificate newCertificateForTests(final PublicKey publicKey, final PrivateKey privateKey,
			String signatureAlgorithm)
			throws CertificateEncodingException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		String subject;
		String issuer;
		Date start;
		Date end;
		BigInteger serialNumber;

		subject = "CN=Test subject";
		issuer = "CN=Test issue";

		start = Date.from(LocalDate.of(2020, Month.JANUARY, 1).atStartOfDay(ZoneId.systemDefault()).toInstant());
		end = Date.from(LocalDate.of(2030, Month.JANUARY, 1).atStartOfDay(ZoneId.systemDefault()).toInstant());
		serialNumber = RandomExtensions.randomSerialNumber();
		return CertFactory.newX509Certificate(publicKey, privateKey, serialNumber, subject, issuer, signatureAlgorithm,
				start, end);
	}

	private TestObjectFactory() {
	}
}
