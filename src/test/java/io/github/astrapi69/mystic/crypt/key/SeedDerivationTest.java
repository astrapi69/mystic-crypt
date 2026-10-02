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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.Signature;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import io.github.astrapi69.mystic.crypt.provider.SecurityProviderSupport;

/**
 * Hierarchical derivation after SLIP-0010 (#163): test vector 1 of the specification for ed25519
 * and for curve25519, every chain of it, from
 * https://github.com/satoshilabs/slips/blob/master/slip-0010.md - the same table lethenon's own
 * derivation is tested against, so the library and its first consumer agree before the consumer
 * switches over.
 * <p>
 * The public keys are checked too: a derivation that is right and a key pair that is wrong would
 * still give every wallet the wrong keys.
 */
class SeedDerivationTest
{

	private static final HexFormat HEX = HexFormat.of();

	private static final byte[] SEED = HEX.parseHex("000102030405060708090a0b0c0d0e0f");

	record Vector(String chain, SeedDerivation.Curve curve, int[] path, String chainCode,
		String privateKey, String publicKey) {
		@Override
		public String toString()
		{
			return curve + " " + chain;
		}
	}

	@BeforeAll
	static void registerBouncyCastle()
	{
		SecurityProviderSupport.ensureBouncyCastle();
	}

	static Stream<Vector> slip10TestVector1()
	{
		SeedDerivation.Curve ed = SeedDerivation.Curve.ED25519;
		SeedDerivation.Curve cv = SeedDerivation.Curve.CURVE25519;
		return Stream.of(
			new Vector("m", ed, new int[] { },
				"90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb",
				"2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7",
				"a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed"),
			new Vector("m/0H", ed, new int[] { 0 },
				"8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69",
				"68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3",
				"8c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c"),
			new Vector("m/0H/1H", ed, new int[] { 0, 1 },
				"a320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14",
				"b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2",
				"1932a5270f335bed617d5b935c80aedb1a35bd9fc1e31acafd5372c30f5c1187"),
			new Vector("m/0H/1H/2H", ed, new int[] { 0, 1, 2 },
				"2e69929e00b5ab250f49c3fb1c12f252de4fed2c1db88387094a0f8c4c9ccd6c",
				"92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9",
				"ae98736566d30ed0e9d2f4486a64bc95740d89c7db33f52121f8ea8f76ff0fc1"),
			new Vector("m/0H/1H/2H/2H", ed, new int[] { 0, 1, 2, 2 },
				"8f6d87f93d750e0efccda017d662a1b31a266e4a6f5993b15f5c1f07f74dd5cc",
				"30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662",
				"8abae2d66361c879b900d204ad2cc4984fa2aa344dd7ddc46007329ac76c429c"),
			new Vector("m/0H/1H/2H/2H/1000000000H", ed, new int[] { 0, 1, 2, 2, 1_000_000_000 },
				"68789923a0cac2cd5a29172a475fe9e0fb14cd6adb5ad98a3fa70333e7afa230",
				"8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793",
				"3c24da049451555d51a7014a37337aa4e12d41e485abccfa46b47dfb2af54b7a"),
			new Vector("m", cv, new int[] { },
				"77997ca3588a1a34f3589279ea2962247abfe5277d52770a44c706378c710768",
				"d70a59c2e68b836cc4bbe8bcae425169b9e2384f3905091e3d60b890e90cd92c",
				"5c7289dc9f7f3ea1c8c2de7323b9fb0781f69c9ecd6de4f095ac89a02dc80577"),
			new Vector("m/0H", cv, new int[] { 0 },
				"349a3973aad771c628bf1f1b4d5e071f18eff2e492e4aa7972a7e43895d6597f",
				"cd7630d7513cbe80515f7317cdb9a47ad4a56b63c3f1dc29583ab8d4cc25a9b2",
				"cb8be6b256ce509008b43ae0dccd69960ad4f7ff2e2868c1fbc9e19ec3ad544b"),
			new Vector("m/0H/1H", cv, new int[] { 0, 1 },
				"2ee5ba14faf2fe9d7ab532451c2be3a0a5375c5e8c44fb31d9ad7edc25cda000",
				"a95f97cfc1a61dd833b882c89d36a78a030ea6b2fbe3ae2a70e4f1fc9008d6b1",
				"e9506455dce2526df42e5e4eb5585eaef712e5f9c6a28bf9fb175d96595ea872"),
			new Vector("m/0H/1H/2H", cv, new int[] { 0, 1, 2 },
				"e1897d5a96459ce2a3d294cb2a6a59050ee61255818c50e03ac4263ef17af084",
				"3d6cce04a9175929da907a90b02176077b9ae050dcef9b959fed978bb2200cdc",
				"18f008fcbc6d1cd8b4fe7a9eba00f6570a9da02a9b0005028cb2731b12ee4118"),
			new Vector("m/0H/1H/2H/2H", cv, new int[] { 0, 1, 2, 2 },
				"1cccc84e2737cfe81b51fbe4c97bbdb000f6a76eddffb9ed03108fbff3ff7e4f",
				"7ae7437efe0a3018999e6f00d72e810ebc50578dbf6728bfa1c7fe73501081a7",
				"512e288a8ef4d869620dc4b06bb06ad2524b350dee5a39fcfeb708dbac65c25c"),
			new Vector("m/0H/1H/2H/2H/1000000000H", cv, new int[] { 0, 1, 2, 2, 1_000_000_000 },
				"8ccf15d55b1dda246b0c1bf3e979a471a82524c1bd0c1eaecccf00dde72168bb",
				"7a59954d387abde3bc703f531f67d659ec2b8a12597ae82824547d7e27991e26",
				"a077fcf5af53d210257d44a86eb2031233ac7237da220434ac01a0bebccc1919"));
	}

	@ParameterizedTest(name = "{0}")
	@MethodSource("slip10TestVector1")
	void derive_givesTheChainCodeAndPrivateKeyOfSlip10(final Vector vector)
	{
		SeedDerivation.Node node = SeedDerivation.derive(vector.curve(), SEED, vector.path());

		assertArrayEquals(HEX.parseHex(vector.chainCode()), node.chainCode());
		assertArrayEquals(HEX.parseHex(vector.privateKey()), node.privateKey());
	}

	@ParameterizedTest(name = "{0}")
	@MethodSource("slip10TestVector1")
	void keyPairOf_givesThePublicKeyOfSlip10(final Vector vector) throws Exception
	{
		KeyPair keyPair = SeedDerivation.keyPairOf(vector.curve(), SEED, vector.path());

		byte[] encoded = keyPair.getPublic().getEncoded();
		// the X.509 encoding ends in the 32 key bytes; SLIP-0010 prints them behind a 00 prefix
		assertArrayEquals(HEX.parseHex(vector.publicKey()),
			Arrays.copyOfRange(encoded, encoded.length - 32, encoded.length));
	}

	@Test
	void anEd25519KeyPairOfASeedSigns_andTheJdkVerifiesWithItsPublicHalf() throws Exception
	{
		KeyPair keyPair = SeedDerivation.keyPairOf(SeedDerivation.Curve.ED25519, SEED, 44, 0, 0);
		byte[] message = "one seed, many keys".getBytes(StandardCharsets.UTF_8);

		Signature signer = Signature.getInstance("Ed25519");
		signer.initSign(keyPair.getPrivate());
		signer.update(message);
		byte[] signature = signer.sign();
		Signature verifier = Signature.getInstance("Ed25519");
		verifier.initVerify(keyPair.getPublic());
		verifier.update(message);

		assertTrue(verifier.verify(signature));
		// the JDK names the algorithm "EdDSA" and puts the curve into the parameters
		assertEquals("Ed25519",
			((java.security.interfaces.EdECPrivateKey)keyPair.getPrivate()).getParams().getName());
	}

	@Test
	void theTwoCurvesGiveDifferentKeys_fromTheSameSeedAndPath()
	{
		assertFalse(
			Arrays.equals(SeedDerivation.derive(SeedDerivation.Curve.ED25519, SEED, 7).privateKey(),
				SeedDerivation.derive(SeedDerivation.Curve.CURVE25519, SEED, 7).privateKey()));
	}

	@Test
	void aNodeHandsOutCopies_soNoCallerCanChangeAnother()
	{
		SeedDerivation.Node node = SeedDerivation.derive(SeedDerivation.Curve.ED25519, SEED);

		node.privateKey()[0] ^= 1;
		node.chainCode()[0] ^= 1;

		assertArrayEquals(
			HEX.parseHex("2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7"),
			node.privateKey());
		assertArrayEquals(
			HEX.parseHex("90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb"),
			node.chainCode());
	}

	@ParameterizedTest(name = "a seed of {0} bytes is refused")
	@ValueSource(ints = { 0, 15, 65 })
	void derive_refusesASeedOutsideSixteenToSixtyFourBytes(final int length)
	{
		IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
			() -> SeedDerivation.derive(SeedDerivation.Curve.ED25519, new byte[length]));

		assertTrue(refused.getMessage().contains(length + " bytes"), refused.getMessage());
	}

	@ParameterizedTest(name = "a seed of {0} bytes is accepted")
	@ValueSource(ints = { 16, 64 })
	void derive_acceptsTheBoundariesOfTheSeedLength(final int length)
	{
		assertEquals(32, SeedDerivation.derive(SeedDerivation.Curve.ED25519, new byte[length])
			.privateKey().length);
	}

	@Test
	void derive_refusesANegativeIndex_whichWouldReadAsAnAlreadyHardenedOne()
	{
		IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
			() -> SeedDerivation.derive(SeedDerivation.Curve.ED25519, SEED, 0, -1));

		assertTrue(refused.getMessage().contains("-1"), refused.getMessage());
	}
}
