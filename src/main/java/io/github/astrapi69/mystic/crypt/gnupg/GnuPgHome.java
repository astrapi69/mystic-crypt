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

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

import org.bouncycastle.gpg.keybox.KeyBlob;
import org.bouncycastle.gpg.keybox.PublicKeyRingBlob;
import org.bouncycastle.gpg.keybox.bc.BcKeyBox;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPCertificate.OpenPGPComponentKey;
import org.bouncycastle.openpgp.api.OpenPGPCertificate.OpenPGPUserId;
import org.bouncycastle.util.encoders.Hex;

/**
 * Reads a GnuPG home with Bouncy Castle's OpenPGP readers, for display: the certificates of its
 * keybox, for every key where its secret part is, and whether gpg keeps a revocation certificate
 * for each primary key.
 * <p>
 * Nothing is written and nothing is decrypted: the keybox holds public keys only, the key files are
 * matched by the public part they carry in the clear, and gpg is never run. That is the line the
 * maintainer's decision for release keys draws (mystic-crypt-ui,
 * docs/decisions/release-key-openpgp-2026-10-29.md): gpg's store is read, never written.
 */
public final class GnuPgHome
{

	/** The keybox gpg keeps its public keys in since version 2.1 */
	static final String KEYBOX = "pubring.kbx";

	/** The keyring of the versions before 2.1, which this reader does not read */
	static final String LEGACY_KEYRING = "pubring.gpg";

	/** Where gpg's agent keeps the secret parts, one file per key */
	static final String PRIVATE_KEYS = "private-keys-v1.d";

	/** Where gpg keeps the revocation certificate it writes with every new primary key */
	static final String REVOCATIONS = "openpgp-revocs.d";

	/** A keybox of a few thousand keys stays far below this; a larger file is not parsed */
	private static final long MAXIMUM_KEYBOX_SIZE = 64L * 1024 * 1024;

	/** The shortest name a key is found by: the long key id */
	private static final int SHORTEST_KEY_NAME = 16;

	private GnuPgHome()
	{
	}

	/**
	 * Reads every certificate of a GnuPG home
	 *
	 * @param home
	 *            the GnuPG home, for example {@code ~/.gnupg}
	 * @return the certificates in the order the keybox holds them, empty when it has no keybox
	 * @throws IOException
	 *             when the home does not exist, holds a keyring of the format before GnuPG 2.1, or
	 *             its keybox cannot be read
	 */
	public static List<KeyRingState> read(final Path home) throws IOException
	{
		if (!Files.isDirectory(home))
		{
			throw new NoSuchFileException(home.toString(), null, "no GnuPG home there");
		}
		SecretKeyFiles secretKeyFiles = SecretKeyFiles.in(home.resolve(PRIVATE_KEYS));
		List<KeyRingState> rings = new ArrayList<>();
		for (PGPPublicKeyRing ring : keyRingsOf(home))
		{
			rings.add(stateOf(ring, secretKeyFiles, home.resolve(REVOCATIONS)));
		}
		return rings;
	}

	/**
	 * Finds a certificate by the fingerprint or the long key id of its primary key, written in any
	 * of the ways people write them: upper or lower case, in groups, with {@code 0x} in front
	 *
	 * @param rings
	 *            the certificates to search
	 * @param name
	 *            the fingerprint or the long key id
	 * @return the certificate, empty when none of them has that primary key
	 */
	public static Optional<KeyRingState> find(final List<KeyRingState> rings, final String name)
	{
		String wanted = name.replaceAll("\\s", "").toUpperCase(Locale.ROOT);
		String key = wanted.startsWith("0X") ? wanted.substring(2) : wanted;
		if (key.length() < SHORTEST_KEY_NAME)
		{
			return Optional.empty();
		}
		return rings.stream().filter(ring -> ring.fingerprint().endsWith(key)).findFirst();
	}

	/**
	 * The GnuPG home gpg itself uses: the one {@code GNUPGHOME} names, else {@code ~/.gnupg}
	 *
	 * @param environment
	 *            the environment to read {@code GNUPGHOME} from
	 * @param userHome
	 *            the user's home directory
	 * @return the home
	 */
	public static Path defaultHome(final Map<String, String> environment, final String userHome)
	{
		String configured = environment.get("GNUPGHOME");
		return configured != null && !configured.isBlank()
			? Path.of(configured)
			: Path.of(userHome, ".gnupg");
	}

	private static List<PGPPublicKeyRing> keyRingsOf(final Path home) throws IOException
	{
		Path keybox = home.resolve(KEYBOX);
		if (!Files.isRegularFile(keybox))
		{
			requireNoLegacyKeyring(home);
			return List.of();
		}
		if (Files.size(keybox) > MAXIMUM_KEYBOX_SIZE)
		{
			throw new IOException(keybox + " is larger than " + MAXIMUM_KEYBOX_SIZE
				+ " bytes, which no keybox of a person's keys reaches; it is not read");
		}
		List<PGPPublicKeyRing> rings = new ArrayList<>();
		try (InputStream in = Files.newInputStream(keybox))
		{
			for (KeyBlob blob : new BcKeyBox(in).getKeyBlobs())
			{
				if (blob instanceof PublicKeyRingBlob publicKeys)
				{
					rings.add(publicKeys.getPGPPublicKeyRing());
				}
			}
		}
		return rings;
	}

	private static void requireNoLegacyKeyring(final Path home) throws IOException
	{
		Path legacy = home.resolve(LEGACY_KEYRING);
		if (Files.exists(legacy))
		{
			throw new IOException(legacy + " is a keyring in the format before GnuPG 2.1, which "
				+ "this view does not read; it reads " + KEYBOX + ", the keybox gpg writes since");
		}
	}

	private static KeyRingState stateOf(final PGPPublicKeyRing ring,
		final SecretKeyFiles secretKeyFiles, final Path revocations)
	{
		OpenPGPCertificate certificate = new OpenPGPCertificate(ring);
		List<KeyState> keys = new ArrayList<>();
		for (OpenPGPComponentKey key : certificate.getKeys())
		{
			keys.add(stateOf(key, secretKeyFiles));
		}
		String fingerprint = fingerprintOf(ring.getPublicKey());
		RevocationCertificate revocationCertificate = RevocationCertificates
			.judge(revocations.resolve(fingerprint + ".rev"), ring.getPublicKey());
		return new KeyRingState(fingerprint, firstUserIdOf(certificate), keys,
			revocationCertificate);
	}

	private static KeyState stateOf(final OpenPGPComponentKey key,
		final SecretKeyFiles secretKeyFiles)
	{
		PGPPublicKey publicKey = key.getPGPPublicKey();
		Date expires = key.getKeyExpirationDate();
		return new KeyState(fingerprintOf(publicKey), key.isPrimaryKey(),
			KeyNames.algorithmOf(publicKey), KeyNames.usageOf(key.getKeyFlags()),
			publicKey.getCreationTime().toInstant(), expires == null ? null : expires.toInstant(),
			secretKeyFiles.of(publicKey.getPublicKeyPacket().getKey()));
	}

	private static String firstUserIdOf(final OpenPGPCertificate certificate)
	{
		return certificate.getAllUserIds().stream().findFirst().map(OpenPGPUserId::getUserId)
			.orElse("");
	}

	private static String fingerprintOf(final PGPPublicKey publicKey)
	{
		return Hex.toHexString(publicKey.getFingerprint()).toUpperCase(Locale.ROOT);
	}
}
