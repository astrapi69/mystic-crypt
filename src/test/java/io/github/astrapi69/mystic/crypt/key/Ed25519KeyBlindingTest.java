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
package io.github.astrapi69.mystic.crypt.key;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.EdECPrivateKeySpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.stream.Stream;

import org.bouncycastle.crypto.digests.KeccakDigest;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;

import io.github.astrapi69.mystic.crypt.provider.SecurityProviderSupport;

/**
 * The unit test class for {@link Ed25519KeyBlinding} and {@link Ed25519ExpandedPrivateKey} (#166).
 * <p>
 * Three referees that this code does not control: Monero's known-answer vectors for the additive
 * derivation on the same curve, the RFC 8032 signatures, and the JDK's own Ed25519 verifier, which
 * has to accept every signature made with a blinded key.
 */
class Ed25519KeyBlindingTest
{

	private static final HexFormat HEX = HexFormat.of();

	/** The DER prefix of an X.509 encoded Ed25519 public key, in front of the 32 raw bytes */
	private static final byte[] X509_PREFIX = HEX.parseHex("302a300506032b6570032100");

	/** The order of the prime subgroup, RFC 8032 section 5.1 */
	private static final BigInteger L = BigInteger.TWO.pow(252)
		.add(new BigInteger("27742317777372353535851937790883648493"));

	private static List<String[]> vectors;

	@BeforeAll
	static void loadVectors() throws IOException
	{
		SecurityProviderSupport.ensureBouncyCastle();
		try (InputStream in = Ed25519KeyBlindingTest.class
			.getResourceAsStream("/ed25519-blinding/monero-vectors.txt"))
		{
			vectors = new String(in.readAllBytes(), StandardCharsets.US_ASCII).lines()
				.map(line -> line.split(" ")).toList();
		}
	}

	private static Stream<Arguments> vectorsOf(final String kind, final int fields)
	{
		return vectors.stream().filter(line -> line[0].equals(kind))
			.filter(line -> line.length == fields)
			.map(line -> Arguments.of((Object)Arrays.copyOfRange(line, 1, fields)));
	}

	static Stream<Arguments> derivedPublicKeys()
	{
		return vectorsOf("derive_public_key", 6);
	}

	static Stream<Arguments> refusedBases()
	{
		return vectorsOf("derive_public_key", 5);
	}

	static Stream<Arguments> derivedSecretKeys()
	{
		return vectorsOf("derive_secret_key", 5);
	}

	static Stream<Arguments> scalarPublicKeys()
	{
		return vectorsOf("secret_key_to_public_key", 4);
	}

	static Stream<Arguments> checkedKeys()
	{
		return vectorsOf("check_key", 3);
	}

	/**
	 * Monero's derivation scalar: Keccak-256 of the derivation and the varint of the output index.
	 * The reduction mod l is the blinding's own job, so it is not done here.
	 */
	private static byte[] moneroTweak(final String derivation, final String index)
	{
		byte[] derivationBytes = HEX.parseHex(derivation);
		byte[] varint = varint(Long.parseLong(index));
		KeccakDigest keccak = new KeccakDigest(256);
		keccak.update(derivationBytes, 0, derivationBytes.length);
		keccak.update(varint, 0, varint.length);
		byte[] digest = new byte[32];
		keccak.doFinal(digest, 0);
		return digest;
	}

	/** Monero's varint: seven bits per byte, lowest first, the high bit marks a following byte */
	private static byte[] varint(final long value)
	{
		byte[] buffer = new byte[10];
		int length = 0;
		long rest = value;
		while (rest >= 0x80)
		{
			buffer[length++] = (byte)((rest & 0x7f) | 0x80);
			rest >>>= 7;
		}
		buffer[length++] = (byte)rest;
		return Arrays.copyOf(buffer, length);
	}

	private static EdECPublicKey publicKeyOf(final byte[] raw) throws GeneralSecurityException
	{
		byte[] encoded = Arrays.copyOf(X509_PREFIX, X509_PREFIX.length + raw.length);
		System.arraycopy(raw, 0, encoded, X509_PREFIX.length, raw.length);
		return (EdECPublicKey)KeyFactory.getInstance("Ed25519")
			.generatePublic(new X509EncodedKeySpec(encoded));
	}

	private static byte[] rawOf(final PublicKey publicKey)
	{
		byte[] encoded = publicKey.getEncoded();
		return Arrays.copyOfRange(encoded, X509_PREFIX.length, encoded.length);
	}

	private static EdECPrivateKey privateKeyOf(final byte[] seed) throws GeneralSecurityException
	{
		return (EdECPrivateKey)KeyFactory.getInstance("Ed25519")
			.generatePrivate(new EdECPrivateKeySpec(NamedParameterSpec.ED25519, seed));
	}

	private static boolean jdkVerifies(final PublicKey publicKey, final byte[] message,
		final byte[] signature) throws GeneralSecurityException
	{
		Signature verifier = Signature.getInstance("Ed25519");
		verifier.initVerify(publicKey);
		verifier.update(message);
		return verifier.verify(signature);
	}

	/**
	 * Whether the JDK accepts a signature. A changed R can stop being a point, and then the JDK
	 * rejects by throwing instead of answering false; both are a rejection.
	 */
	private static boolean jdkAccepts(final PublicKey publicKey, final byte[] message,
		final byte[] signature) throws GeneralSecurityException
	{
		try
		{
			return jdkVerifies(publicKey, message, signature);
		}
		catch (SignatureException rejected)
		{
			return false;
		}
	}

	/** 32 little-endian bytes of a non-negative integer, for tweaks given as numbers */
	private static byte[] littleEndian(final BigInteger value, final int length)
	{
		byte[] bigEndian = value.toByteArray();
		byte[] result = new byte[length];
		for (int i = 0; i < bigEndian.length && i < length; i++)
		{
			result[i] = bigEndian[bigEndian.length - 1 - i];
		}
		return result;
	}

	@ParameterizedTest(name = "derive_public_key {index}")
	@MethodSource("derivedPublicKeys")
	void blindingAPublicKeyAddsTheTweakTimesTheBasePointLikeMonero(final String[] fields)
		throws Exception
	{
		EdECPublicKey base = publicKeyOf(HEX.parseHex(fields[2]));

		EdECPublicKey derived = Ed25519KeyBlinding.blind(base, moneroTweak(fields[0], fields[1]));

		assertEquals(fields[4], HEX.formatHex(rawOf(derived)));
	}

	@ParameterizedTest(name = "derive_public_key, base not a point {index}")
	@MethodSource("refusedBases")
	void blindingRefusesABaseThatIsNotAPoint(final String[] fields) throws Exception
	{
		EdECPublicKey base = publicKeyOf(HEX.parseHex(fields[2]));
		byte[] tweak = moneroTweak(fields[0], fields[1]);

		IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
			() -> Ed25519KeyBlinding.blind(base, tweak));

		assertTrue(refused.getMessage().contains("not a point"), refused.getMessage());
	}

	@ParameterizedTest(name = "derive_secret_key {index}")
	@MethodSource("derivedSecretKeys")
	void blindingAScalarAddsTheTweakModLLikeMonero(final String[] fields)
	{
		Ed25519ExpandedPrivateKey base = Ed25519ExpandedPrivateKey.ofScalar(HEX.parseHex(fields[2]),
			new byte[32]);

		Ed25519ExpandedPrivateKey derived = base.blind(moneroTweak(fields[0], fields[1]));

		assertEquals(fields[3], HEX.formatHex(derived.scalarBytes()));
	}

	@ParameterizedTest(name = "secret_key_to_public_key {index}")
	@MethodSource("scalarPublicKeys")
	void aRawScalarHasThePublicKeyMoneroComputes(final String[] fields)
	{
		Ed25519ExpandedPrivateKey key = Ed25519ExpandedPrivateKey.ofScalar(HEX.parseHex(fields[0]),
			new byte[32]);

		assertEquals(fields[2], HEX.formatHex(rawOf(key.publicKey())));
	}

	@ParameterizedTest(name = "check_key {index}")
	@MethodSource("checkedKeys")
	void decodingAgreesWithMoneroOnWhatIsAPoint(final String[] fields)
	{
		assertEquals(Boolean.parseBoolean(fields[1]),
			Ed25519Points.isPoint(HEX.parseHex(fields[0])));
	}

	@ParameterizedTest(name = "RFC 8032 TEST {index}")
	@CsvSource({
			"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60, d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a, '', e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
			"4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb, 3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c, 72, 92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
			"c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7, fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025, af82, 6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a" })
	void theUnblindedExpandedKeySignsExactlyLikeRfc8032(final String seed, final String publicKey,
		final String message, final String signature) throws Exception
	{
		Ed25519ExpandedPrivateKey key = Ed25519ExpandedPrivateKey
			.of(privateKeyOf(HEX.parseHex(seed)));

		assertEquals(publicKey, HEX.formatHex(rawOf(key.publicKey())));
		assertEquals(signature, HEX.formatHex(key.sign(HEX.parseHex(message))));
	}

	static Stream<Arguments> tweaks()
	{
		return Stream.of(Arguments.of("zero", new byte[32]),
			Arguments.of("one", littleEndian(BigInteger.ONE, 32)),
			Arguments.of("l - 1", littleEndian(L.subtract(BigInteger.ONE), 32)),
			Arguments.of("exactly l, which is zero", littleEndian(L, 32)),
			Arguments.of("l + 1, which is one", littleEndian(L.add(BigInteger.ONE), 32)),
			Arguments.of("32 bytes of 0xff", filled(32)),
			Arguments.of("64 bytes of 0xff, a whole SHA-512", filled(64)),
			Arguments.of("a single byte", new byte[] { 7 }));
	}

	private static byte[] filled(final int length)
	{
		byte[] bytes = new byte[length];
		Arrays.fill(bytes, (byte)0xff);
		return bytes;
	}

	@ParameterizedTest(name = "tweak {0}")
	@MethodSource("tweaks")
	void bothSidesOfABlindingAgreeAndTheJdkVerifiesTheSignature(final String name,
		final byte[] tweak) throws Exception
	{
		KeyPair keyPair = Ed25519Signer.newKeyPair();
		byte[] message = ("a payment to a one-time destination, tweak " + name)
			.getBytes(StandardCharsets.UTF_8);

		Ed25519ExpandedPrivateKey blindedPrivate = Ed25519KeyBlinding
			.blind((EdECPrivateKey)keyPair.getPrivate(), tweak);
		EdECPublicKey blindedPublic = Ed25519KeyBlinding.blind((EdECPublicKey)keyPair.getPublic(),
			tweak);
		byte[] signature = blindedPrivate.sign(message);

		assertArrayEquals(rawOf(blindedPublic), rawOf(blindedPrivate.publicKey()));
		assertTrue(jdkVerifies(blindedPublic, message, signature));
	}

	@Test
	void theJdkRejectsABlindedSignatureWithOneByteChanged() throws Exception
	{
		KeyPair keyPair = Ed25519Signer.newKeyPair();
		byte[] tweak = littleEndian(BigInteger.valueOf(1984), 32);
		byte[] message = "one byte changed".getBytes(StandardCharsets.UTF_8);
		Ed25519ExpandedPrivateKey blinded = Ed25519KeyBlinding
			.blind((EdECPrivateKey)keyPair.getPrivate(), tweak);
		byte[] signature = blinded.sign(message);

		for (int position : new int[] { 0, 31, 32, 63 })
		{
			byte[] changed = signature.clone();
			changed[position] ^= 1;
			assertFalse(jdkAccepts(blinded.publicKey(), message, changed), "position " + position);
		}
	}

	@Test
	void aBlindedSignatureDoesNotVerifyUnderTheUnblindedKey() throws Exception
	{
		KeyPair keyPair = Ed25519Signer.newKeyPair();
		byte[] message = "the spend key alone".getBytes(StandardCharsets.UTF_8);
		Ed25519ExpandedPrivateKey blinded = Ed25519KeyBlinding
			.blind((EdECPrivateKey)keyPair.getPrivate(), littleEndian(BigInteger.TWO, 32));

		assertFalse(jdkVerifies(keyPair.getPublic(), message, blinded.sign(message)));
		assertNotEquals(HEX.formatHex(rawOf(keyPair.getPublic())),
			HEX.formatHex(rawOf(blinded.publicKey())));
	}

	@Test
	void theSameKeyAndTweakGiveTheSameSignatureAndDifferentTweaksDifferentNonces() throws Exception
	{
		EdECPrivateKey privateKey = (EdECPrivateKey)Ed25519Signer.newKeyPair().getPrivate();
		byte[] message = "deterministic".getBytes(StandardCharsets.UTF_8);

		byte[] first = Ed25519KeyBlinding.blind(privateKey, littleEndian(BigInteger.ONE, 32))
			.sign(message);
		byte[] again = Ed25519KeyBlinding.blind(privateKey, littleEndian(BigInteger.ONE, 32))
			.sign(message);
		byte[] other = Ed25519KeyBlinding.blind(privateKey, littleEndian(BigInteger.TWO, 32))
			.sign(message);

		assertArrayEquals(first, again);
		assertFalse(Arrays.equals(Arrays.copyOf(first, 32), Arrays.copyOf(other, 32)),
			"two tweaks of one key must not share the nonce point R");
	}

	@Test
	void aTweakOfLBlindsExactlyLikeATweakOfZero() throws Exception
	{
		EdECPrivateKey privateKey = (EdECPrivateKey)Ed25519Signer.newKeyPair().getPrivate();
		byte[] message = "l is zero".getBytes(StandardCharsets.UTF_8);

		byte[] withZero = Ed25519KeyBlinding.blind(privateKey, new byte[32]).sign(message);
		byte[] withL = Ed25519KeyBlinding.blind(privateKey, littleEndian(L, 32)).sign(message);

		assertArrayEquals(withZero, withL);
	}

	@ParameterizedTest(name = "{0}")
	@CsvSource({
			"the neutral element with the sign bit set, 0100000000000000000000000000000000000000000000000000000000000080",
			"y = p is not canonical, edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
			"y = p + 1 is not canonical, eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
			"31 bytes, 0100000000000000000000000000000000000000000000000000000000000000ff" })
	void decodingRefusesWhatRfc8032Refuses(final String name, final String encoded)
	{
		byte[] bytes = HEX.parseHex(encoded);
		byte[] input = name.startsWith("31") ? Arrays.copyOf(bytes, 31) : bytes;

		assertFalse(Ed25519Points.isPoint(input));
		assertThrows(IllegalArgumentException.class, () -> Ed25519Points.decode(input));
	}

	@ParameterizedTest(name = "{0}")
	@CsvSource({
			"the neutral element, 0100000000000000000000000000000000000000000000000000000000000000",
			"the point of order two, ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
			"the base point, 5866666666666666666666666666666666666666666666666666666666666666" })
	void theSpecialPointsOfTheMapSurviveTheRoundTrip(final String name, final String encoded)
	{
		byte[] bytes = HEX.parseHex(encoded);

		assertArrayEquals(bytes, Ed25519Points.encode(Ed25519Points.decode(bytes)));
	}

	@Test
	void theNeutralElementIsTheWeierstrassPointAtInfinity()
	{
		assertTrue(Ed25519Points
			.decode(
				HEX.parseHex("0100000000000000000000000000000000000000000000000000000000000000"))
			.isInfinity());
		assertEquals("0100000000000000000000000000000000000000000000000000000000000000",
			HEX.formatHex(Ed25519Points.encode(Ed25519Points.BASE.multiply(L))));
	}

	@Test
	void theBasePointMapsToBouncyCastlesCurve25519Generator()
	{
		org.bouncycastle.math.ec.ECPoint generator = org.bouncycastle.crypto.ec.CustomNamedCurves
			.getByName("curve25519").getG().normalize();
		org.bouncycastle.math.ec.ECPoint base = Ed25519Points.BASE.normalize();

		assertEquals(generator.getAffineXCoord(), base.getAffineXCoord());
		assertTrue(generator.equals(base) || generator.equals(base.negate()));
	}

	@Test
	void theInverseMapNeedsNoBranchForUMinusOneOrAnotherPointOfOrderTwo()
	{
		BigInteger p = BigInteger.TWO.pow(255).subtract(BigInteger.valueOf(19));
		BigInteger a = BigInteger.valueOf(486662);
		BigInteger half = p.subtract(BigInteger.ONE).shiftRight(1);
		// Euler's criterion: z^((p-1)/2) = -1 means z is not a square
		BigInteger minusOne = p.subtract(BigInteger.ONE);

		// u = -1 would need v^2 = A - 2
		assertEquals(minusOne, a.subtract(BigInteger.TWO).modPow(half, p));
		// v = 0 with u != 0 would need a root of u^2 + A u + 1, i.e. A^2 - 4 a square
		assertEquals(minusOne, a.multiply(a).subtract(BigInteger.valueOf(4)).modPow(half, p));
	}

	@Test
	void aPrivateKeyWithoutSeedBytesIsRefusedWithTheReason()
	{
		EdECPrivateKey withoutSeed = new EdECPrivateKey()
		{
			private static final long serialVersionUID = 1L;

			@Override
			public java.util.Optional<byte[]> getBytes()
			{
				return java.util.Optional.empty();
			}

			@Override
			public NamedParameterSpec getParams()
			{
				return NamedParameterSpec.ED25519;
			}

			@Override
			public String getAlgorithm()
			{
				return "Ed25519";
			}

			@Override
			public String getFormat()
			{
				return null;
			}

			@Override
			public byte[] getEncoded()
			{
				return null;
			}
		};

		IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
			() -> Ed25519KeyBlinding.blind(withoutSeed, new byte[32]));

		assertTrue(refused.getMessage().contains("seed"), refused.getMessage());
	}

	/**
	 * Runs an action with every provider that offers SHA-512 and Ed25519 removed, and puts them
	 * back at their old positions afterwards. The tests of this module run sequentially in one JVM,
	 * like the other tests here that remove providers.
	 */
	private static void withoutProviders(final Runnable action)
	{
		Provider[] removed = Arrays.stream(Security.getProviders())
			.filter(provider -> List.of("SUN", "SunEC", "BC").contains(provider.getName()))
			.toArray(Provider[]::new);
		List<Provider> before = List.of(Security.getProviders());
		try
		{
			Arrays.stream(removed).forEach(provider -> Security.removeProvider(provider.getName()));
			action.run();
		}
		finally
		{
			for (Provider provider : removed)
			{
				Security.insertProviderAt(provider, before.indexOf(provider) + 1);
			}
		}
		assertEquals(before, List.of(Security.getProviders()));
	}

	@Test
	void aPlatformWithoutSha512IsReportedNotSwallowed() throws Exception
	{
		EdECPrivateKey privateKey = (EdECPrivateKey)Ed25519Signer.newKeyPair().getPrivate();

		withoutProviders(() -> {
			IllegalStateException reported = assertThrows(IllegalStateException.class,
				() -> Ed25519ExpandedPrivateKey.of(privateKey));
			assertTrue(reported.getMessage().contains("SHA-512"), reported.getMessage());
		});
	}

	@Test
	void aPlatformWithoutEd25519KeysIsReportedNotSwallowed() throws Exception
	{
		EdECPublicKey publicKey = (EdECPublicKey)Ed25519Signer.newKeyPair().getPublic();

		withoutProviders(() -> {
			IllegalStateException reported = assertThrows(IllegalStateException.class,
				() -> Ed25519KeyBlinding.blind(publicKey, new byte[32]));
			assertTrue(reported.getMessage().contains("Ed25519"), reported.getMessage());
		});
	}

	@Test
	void theSeedBytesAKeyHandsOutAreWipedAfterExpansion() throws Exception
	{
		byte[] seed = HEX
			.parseHex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
		EdECPrivateKey handingOutItsOwnArray = new EdECPrivateKey()
		{
			private static final long serialVersionUID = 1L;

			@Override
			public java.util.Optional<byte[]> getBytes()
			{
				return java.util.Optional.of(seed);
			}

			@Override
			public NamedParameterSpec getParams()
			{
				return NamedParameterSpec.ED25519;
			}

			@Override
			public String getAlgorithm()
			{
				return "Ed25519";
			}

			@Override
			public String getFormat()
			{
				return null;
			}

			@Override
			public byte[] getEncoded()
			{
				return null;
			}
		};

		Ed25519ExpandedPrivateKey expanded = Ed25519ExpandedPrivateKey.of(handingOutItsOwnArray);

		assertArrayEquals(new byte[32], seed);
		assertEquals("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
			HEX.formatHex(rawOf(expanded.publicKey())));
	}

	@ParameterizedTest(name = "{0}")
	@CsvSource({ "zero, 0", "one, 1",
			"2^255 - 1 (32 bytes in big-endian), 57896044618658097711785492504343953926634992332820282019728792003956564819967",
			"2^255 (33 bytes in big-endian with the sign byte), 57896044618658097711785492504343953926634992332820282019728792003956564819968",
			"2^256 - 1 (the largest the contract allows), 115792089237316195423570985008687907853269984665640564039457584007913129639935" })
	void littleEndianRoundTripsEveryValueBelowTwoToThe256(final String name, final String value)
	{
		BigInteger number = new BigInteger(value);

		byte[] encoded = Ed25519Scalars.toLittleEndian(number);

		assertEquals(32, encoded.length);
		assertEquals(number, Ed25519Scalars.fromLittleEndian(encoded));
		assertArrayEquals(littleEndian(number, 32), encoded);
	}

	@Test
	void anEmptyTweakIsRefused() throws Exception
	{
		KeyPair keyPair = Ed25519Signer.newKeyPair();

		assertThrows(IllegalArgumentException.class,
			() -> Ed25519KeyBlinding.blind((EdECPublicKey)keyPair.getPublic(), new byte[0]));
		assertThrows(IllegalArgumentException.class,
			() -> Ed25519KeyBlinding.blind((EdECPrivateKey)keyPair.getPrivate(), new byte[0]));
	}
}
