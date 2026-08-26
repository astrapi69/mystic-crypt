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
package io.github.astrapi69.mystic.crypt.ssl;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import io.github.astrapi69.mystic.crypt.provider.SecurityProviderSupport;

/**
 * Builds a self-signed X.509 certificate that carries the extensions which make a certificate mean
 * something: basic constraints, key usage and subject alternative names.
 * <p>
 * A certificate without them is of limited use - a verifier cannot tell a CA from an end entity,
 * cannot tell what the key may be used for, and cannot match the certificate to a host name.
 */
public final class SelfSignedCertificateFactory
{

	/** The key algorithm whose signatures RFC 4055 requires to be PSS. */
	private static final String RSASSA_PSS = "RSASSA-PSS";

	private SelfSignedCertificateFactory()
	{
	}

	/**
	 * What kind of certificate this is, and how deep a chain below it may go.
	 *
	 * @param certificateAuthority
	 *            whether this certificate may sign other certificates
	 * @param pathLength
	 *            how many CAs may appear below it, or null for no limit
	 */
	public record BasicConstraintsSpec(boolean certificateAuthority, Integer pathLength) {
	}

	/**
	 * One subject alternative name.
	 *
	 * @param type
	 *            the kind of name: {@code dns}, {@code ip}, {@code email} or {@code uri}
	 * @param value
	 *            the name itself
	 */
	public record SubjectAlternativeName(String type, String value) {

		/**
		 * Parses a name written as {@code type:value}.
		 *
		 * @param text
		 *            the text to parse
		 * @return the parsed name
		 * @throws IllegalArgumentException
		 *             if the text has no type or an unknown one
		 */
		public static SubjectAlternativeName parse(final String text)
		{
			final int colon = text == null ? -1 : text.indexOf(':');
			if (colon < 1 || colon == text.length() - 1)
			{
				throw new IllegalArgumentException("a subject alternative name is written as "
					+ "type:value, e.g. dns:example.org, ip:10.0.0.1, email:someone@example.org "
					+ "or uri:https://example.org, but was '" + text + "'");
			}
			return new SubjectAlternativeName(text.substring(0, colon).toLowerCase(Locale.ROOT),
				text.substring(colon + 1));
		}

		/**
		 * The tag this name carries inside the extension.
		 *
		 * @return the general name tag
		 */
		public int tag()
		{
			return switch (type)
			{
				case "dns" -> GeneralName.dNSName;
				case "ip" -> GeneralName.iPAddress;
				case "email" -> GeneralName.rfc822Name;
				case "uri" -> GeneralName.uniformResourceIdentifier;
				default -> throw new IllegalArgumentException("'" + type + "' is not a subject "
					+ "alternative name type. Use dns, ip, email or uri.");
			};
		}
	}

	/**
	 * Everything a caller can put into the certificate beyond the name and the validity.
	 *
	 * @param basicConstraints
	 *            the basic constraints, or null to leave the extension out
	 * @param keyUsages
	 *            the key usage names, empty to leave the extension out
	 * @param subjectAlternativeNames
	 *            the subject alternative names, empty to leave the extension out
	 * @param criticalExtensions
	 *            the names of the extensions to mark critical, from {@code basic-constraints},
	 *            {@code key-usage} and {@code san}
	 */
	public record Extensions(BasicConstraintsSpec basicConstraints, List<String> keyUsages,
		List<SubjectAlternativeName> subjectAlternativeNames, List<String> criticalExtensions) {
	}

	/**
	 * Creates a self-signed certificate for the given key pair.
	 *
	 * @param keyPair
	 *            the key pair whose public half the certificate carries and whose private half
	 *            signs it
	 * @param distinguishedName
	 *            the name that is both issuer and subject
	 * @param days
	 *            how long the certificate is valid, from now
	 * @param signatureAlgorithm
	 *            the signature algorithm, e.g. {@code SHA256withRSA}
	 * @param extensions
	 *            the extensions to write
	 * @return the certificate
	 * @throws Exception
	 *             if the certificate cannot be built or signed
	 */
	public static X509Certificate create(final KeyPair keyPair, final X500Name distinguishedName,
		final int days, final String signatureAlgorithm, final Extensions extensions)
		throws Exception
	{
		SecurityProviderSupport.ensureBouncyCastle();
		requireSignatureFitsTheKey(keyPair, signatureAlgorithm);

		final Instant now = Instant.now();
		final JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
			distinguishedName, newSerialNumber(), Date.from(now),
			Date.from(now.plus(days, ChronoUnit.DAYS)), distinguishedName, keyPair.getPublic());
		addExtensions(builder, extensions);

		return converter().getCertificate(builder.build(newSigner(signatureAlgorithm, keyPair)));
	}

	/**
	 * Refuses a signature algorithm that the key cannot legitimately be used with.
	 * <p>
	 * RFC 4055 requires an RSASSA-PSS key to be used with a PSS signature; signing with
	 * {@code SHA256withRSA} instead produces a certificate that some verifiers reject, and it does
	 * so quietly. This is the mistake that was made in the UI and caught in review, so the library
	 * refuses the combination rather than producing that certificate.
	 *
	 * @param keyPair
	 *            the key pair that will sign
	 * @param signatureAlgorithm
	 *            the signature algorithm asked for
	 * @throws IllegalArgumentException
	 *             if the combination is not valid
	 */
	static void requireSignatureFitsTheKey(final KeyPair keyPair, final String signatureAlgorithm)
	{
		final String keyAlgorithm = keyPair.getPrivate().getAlgorithm();
		if (!RSASSA_PSS.equalsIgnoreCase(keyAlgorithm))
		{
			return;
		}
		final String normalized = signatureAlgorithm.toUpperCase(Locale.ROOT);
		if (normalized.contains("MGF1") || normalized.contains("PSS"))
		{
			return;
		}
		throw new IllegalArgumentException("an " + RSASSA_PSS + " key must be used with a PSS "
			+ "signature: RFC 4055 requires SHA256withRSAandMGF1 (or another ...andMGF1 name), "
			+ "not '" + signatureAlgorithm + "'. A certificate signed the other way is rejected by "
			+ "some verifiers.");
	}

	private static void addExtensions(final JcaX509v3CertificateBuilder builder,
		final Extensions extensions) throws Exception
	{
		final BasicConstraintsSpec basicConstraints = extensions.basicConstraints();
		if (basicConstraints != null)
		{
			builder.addExtension(Extension.basicConstraints,
				extensions.criticalExtensions().contains("basic-constraints"),
				newBasicConstraints(basicConstraints));
		}
		if (!extensions.keyUsages().isEmpty())
		{
			builder.addExtension(Extension.keyUsage,
				extensions.criticalExtensions().contains("key-usage"),
				new KeyUsage(keyUsageBits(extensions.keyUsages())));
		}
		if (!extensions.subjectAlternativeNames().isEmpty())
		{
			builder.addExtension(Extension.subjectAlternativeName,
				extensions.criticalExtensions().contains("san"),
				newGeneralNames(extensions.subjectAlternativeNames()));
		}
	}

	/**
	 * Builds the signer, preferring Bouncy Castle but not insisting on it.
	 * <p>
	 * Bouncy Castle is preferred because an elliptic curve key on a named curve has to be signed by
	 * the provider that understands it. It cannot be insisted on: a post-quantum key such as ML-DSA
	 * comes from the JDK's own provider since JDK 24, and Bouncy Castle refuses a key it did not
	 * produce with "unknown private key passed to ML-DSA". Naming it unconditionally is what made
	 * this factory unable to certify ML-DSA keys, which the factory it replaced could.
	 *
	 * @param signatureAlgorithm
	 *            the signature algorithm
	 * @param keyPair
	 *            the key pair whose private half signs
	 * @return the signer
	 * @throws OperatorCreationException
	 *             if no provider can sign with this key and algorithm
	 */
	private static ContentSigner newSigner(final String signatureAlgorithm, final KeyPair keyPair)
		throws OperatorCreationException
	{
		try
		{
			return new JcaContentSignerBuilder(signatureAlgorithm)
				.setProvider(BouncyCastleProvider.PROVIDER_NAME).build(keyPair.getPrivate());
		}
		catch (final OperatorCreationException notABouncyCastleKey)
		{
			return new JcaContentSignerBuilder(signatureAlgorithm).build(keyPair.getPrivate());
		}
	}

	/**
	 * Builds the certificate converter, with the same preference and for the same reason as
	 * {@link #newSigner(String, KeyPair)}.
	 *
	 * @return the converter
	 */
	private static JcaX509CertificateConverter converter()
	{
		return new JcaX509CertificateConverter();
	}

	private static BasicConstraints newBasicConstraints(final BasicConstraintsSpec specification)
	{
		if (!specification.certificateAuthority())
		{
			return new BasicConstraints(false);
		}
		return specification.pathLength() == null
			? new BasicConstraints(true)
			: new BasicConstraints(specification.pathLength());
	}

	private static GeneralNames newGeneralNames(final List<SubjectAlternativeName> names)
	{
		final List<GeneralName> generalNames = new ArrayList<>(names.size());
		for (final SubjectAlternativeName name : names)
		{
			generalNames.add(new GeneralName(name.tag(), name.value()));
		}
		return new GeneralNames(generalNames.toArray(new GeneralName[0]));
	}

	/**
	 * Turns the key usage names into the bit set the extension carries.
	 *
	 * @param names
	 *            the key usage names
	 * @return the combined bits
	 * @throws IllegalArgumentException
	 *             if a name is not a key usage
	 */
	static int keyUsageBits(final List<String> names)
	{
		int bits = 0;
		for (final String name : names)
		{
			bits |= keyUsageBit(name.trim());
		}
		return bits;
	}

	private static int keyUsageBit(final String name)
	{
		return switch (name.toLowerCase(Locale.ROOT))
		{
			case "digitalsignature" -> KeyUsage.digitalSignature;
			case "nonrepudiation", "contentcommitment" -> KeyUsage.nonRepudiation;
			case "keyencipherment" -> KeyUsage.keyEncipherment;
			case "dataencipherment" -> KeyUsage.dataEncipherment;
			case "keyagreement" -> KeyUsage.keyAgreement;
			case "keycertsign" -> KeyUsage.keyCertSign;
			case "crlsign" -> KeyUsage.cRLSign;
			case "encipheronly" -> KeyUsage.encipherOnly;
			case "decipheronly" -> KeyUsage.decipherOnly;
			default -> throw new IllegalArgumentException("'" + name + "' is not a key usage. Use "
				+ "digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment, "
				+ "keyAgreement, keyCertSign, cRLSign, encipherOnly or decipherOnly.");
		};
	}

	private static BigInteger newSerialNumber()
	{
		return new BigInteger(159, new SecureRandom());
	}
}
