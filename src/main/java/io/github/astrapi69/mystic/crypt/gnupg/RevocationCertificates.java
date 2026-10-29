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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.System.Logger.Level;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;

/**
 * Judges the revocation certificate gpg keeps for a primary key in {@code openpgp-revocs.d}. gpg
 * writes it when the key is generated, as an armored key revocation signature whose first armor
 * line it comments out with a {@code :}, so that the file is not imported by accident.
 */
final class RevocationCertificates
{

	private static final System.Logger LOGGER = System
		.getLogger(RevocationCertificates.class.getName());

	/** A revocation certificate is under a kilobyte; anything far beyond is not one */
	private static final long MAXIMUM_FILE_SIZE = 64 * 1024;

	private RevocationCertificates()
	{
	}

	/**
	 * Whether the given file holds a key revocation signature that verifies against the primary key
	 *
	 * @param file
	 *            the certificate file, which need not exist
	 * @param primaryKey
	 *            the primary key it is meant to revoke
	 * @return absent, valid, or not valid
	 */
	static RevocationCertificate judge(final Path file, final PGPPublicKey primaryKey)
	{
		if (!Files.isRegularFile(file))
		{
			return RevocationCertificate.ABSENT;
		}
		try
		{
			for (PGPSignature signature : signaturesIn(file))
			{
				if (revokes(signature, primaryKey))
				{
					return RevocationCertificate.VALID;
				}
			}
		}
		catch (IOException | PGPException exception)
		{
			LOGGER.log(Level.WARNING, "could not read the revocation certificate " + file,
				exception);
		}
		return RevocationCertificate.NOT_VALID;
	}

	private static boolean revokes(final PGPSignature signature, final PGPPublicKey primaryKey)
		throws PGPException
	{
		if (signature.getSignatureType() != PGPSignature.KEY_REVOCATION
			|| signature.getKeyID() != primaryKey.getKeyID())
		{
			return false;
		}
		signature.init(new BcPGPContentVerifierBuilderProvider(), primaryKey);
		return signature.verifyCertification(primaryKey);
	}

	private static List<PGPSignature> signaturesIn(final Path file) throws IOException
	{
		if (Files.size(file) > MAXIMUM_FILE_SIZE)
		{
			throw new IOException("larger than a revocation certificate");
		}
		// gpg writes the explanation above the armor in the user's language, so the file is not
		// ASCII; ISO-8859-1 maps every byte to one character and back unchanged
		String armored = Files.readString(file, StandardCharsets.ISO_8859_1)
			.replace("\n:-----BEGIN", "\n-----BEGIN");
		List<PGPSignature> signatures = new ArrayList<>();
		try (InputStream in = new ArmoredInputStream(
			new ByteArrayInputStream(armored.getBytes(StandardCharsets.ISO_8859_1))))
		{
			PGPObjectFactory objects = new PGPObjectFactory(in, new BcKeyFingerprintCalculator());
			for (Object object = objects.nextObject(); object != null; object = objects
				.nextObject())
			{
				if (object instanceof PGPSignatureList list)
				{
					list.forEach(signatures::add);
				}
			}
		}
		return signatures;
	}
}
