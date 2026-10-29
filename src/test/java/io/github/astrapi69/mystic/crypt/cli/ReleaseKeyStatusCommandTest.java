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
package io.github.astrapi69.mystic.crypt.cli;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Instant;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import io.github.astrapi69.json.JsonStringToObjectExtensions;
import io.github.astrapi69.mystic.crypt.gnupg.GnuPgHome;
import io.github.astrapi69.mystic.crypt.gnupg.KeyRingState;
import io.github.astrapi69.mystic.crypt.gnupg.KeyState;
import io.github.astrapi69.mystic.crypt.gnupg.RevocationCertificate;
import io.github.astrapi69.mystic.crypt.gnupg.SecretPart;
import io.github.astrapi69.mystic.crypt.gnupg.ThrowawayGnuPgHome;

/**
 * The {@code release-key status} command against a GnuPG home gpg wrote: a release key with its
 * primary key offline and a signing subkey that expires, and a second certificate
 */
class ReleaseKeyStatusCommandTest extends AbstractCliTest
{

	@TempDir
	static Path directory;

	private static ThrowawayGnuPgHome home;

	private static String release;

	@BeforeAll
	static void writeTheHomeWithGpg() throws IOException
	{
		home = ThrowawayGnuPgHome.create(directory.resolve("home"));
		release = home.generate("Release Test <release@example.org>", "ed25519", "sign,cert", "0");
		home.addSubkey(release, "ed25519", "sign", "2y");
		home.takePrimaryOffline(release);
		home.generate("Other Test <other@example.org>", "ed25519", "sign,cert", "0");
	}

	@AfterAll
	static void stopTheAgent() throws IOException
	{
		home.close();
	}

	@Test
	@DisplayName("the readable output names every key with its use, expiry and secret part")
	void status_printsEveryKey()
	{
		assertEquals(0, run("release-key", "status", "--home", home.directory().toString()), err);

		assertTrue(out.contains("2 certificate(s)"), out);
		assertTrue(out.contains("Release Test <release@example.org>"), out);
		assertTrue(out.contains("Other Test <other@example.org>"), out);
		List<String> releaseKeys = out.lines().filter(line -> line.contains("ed25519"))
			.filter(line -> line.contains("[S")).toList();
		assertTrue(releaseKeys.stream().anyMatch(line -> line.contains("primary")
			&& line.contains("[SC]") && line.contains("secret offline")), out);
		assertTrue(releaseKeys.stream().anyMatch(line -> line.contains("subkey")
			&& line.contains("[S]") && line.contains("secret here")), out);
		assertTrue(out.contains("revocation certificate: valid"), out);
	}

	@Test
	@DisplayName("with --key only the release key is printed")
	void status_withAKey_printsOnlyIt()
	{
		assertEquals(0, run("release-key", "status", "--home", home.directory().toString(), "--key",
			release.substring(release.length() - 16)), err);

		assertTrue(out.contains("Release Test <release@example.org>"), out);
		assertFalse(out.contains("Other Test"), out);
	}

	@Test
	@DisplayName("--json prints the same facts as JSON a parser reads")
	@SuppressWarnings("unchecked")
	void status_json_isParsableAndComplete() throws Exception
	{
		assertEquals(0, run("release-key", "status", "--home", home.directory().toString(), "--key",
			release, "--json"), err);

		Map<String, Object> status = JsonStringToObjectExtensions.toObject(out, Map.class);
		assertEquals(home.directory().toString(), status.get("home"));
		List<Map<String, Object>> certificates = (List<Map<String, Object>>)status
			.get("certificates");
		assertEquals(1, certificates.size());
		Map<String, Object> certificate = certificates.get(0);
		assertEquals(release, certificate.get("fingerprint"));
		assertEquals("Release Test <release@example.org>", certificate.get("userId"));
		assertEquals("VALID", certificate.get("revocationCertificate"));
		List<Map<String, Object>> keys = (List<Map<String, Object>>)certificate.get("keys");
		assertEquals(List.of("OFFLINE", "HERE"),
			keys.stream().map(key -> key.get("secret")).toList());
		assertEquals(List.of("SC", "S"), keys.stream().map(key -> key.get("usage")).toList());
		assertEquals(null, keys.get(0).get("expires"));
		assertTrue(String.valueOf(keys.get(1).get("expires")).matches("\\d{4}-\\d\\d-\\d\\dT.*Z"),
			keys.toString());
	}

	@Test
	@DisplayName("a key that is not in the home is named, with exit code 1")
	void status_aKeyThatIsNotThere_exitsWithOne()
	{
		assertEquals(1, run("release-key", "status", "--home", home.directory().toString(), "--key",
			"0000000000000000"));

		assertTrue(err.contains("0000000000000000"), err);
		assertTrue(err.contains(home.directory().toString()), err);
	}

	@Test
	@DisplayName("a home that cannot be read gives the reason, with exit code 2")
	void status_aMissingHome_exitsWithTwo()
	{
		Path missing = directory.resolve("no-such-home");

		assertEquals(2, run("release-key", "status", "--home", missing.toString()));

		assertTrue(err.contains(missing.toString()), err);
		assertEquals("", out);
	}

	@Test
	@DisplayName("without --home the home gpg itself uses is read: GNUPGHOME, else ~/.gnupg")
	void status_withoutAHome_readsTheDefaultHome()
	{
		String userHome = System.getProperty("user.home");
		System.setProperty("user.home", directory.resolve("a-user-without-gnupg").toString());
		try
		{
			Path expected = GnuPgHome.defaultHome(System.getenv(), System.getProperty("user.home"));

			run("release-key", "status");

			assertTrue((out + err).contains(expected.toString()), out + err);
		}
		finally
		{
			System.setProperty("user.home", userHome);
		}
	}

	@Test
	@DisplayName("a key that expired before today says so, one that expires today does not")
	void readable_saysWhenAKeyExpired()
	{
		KeyState expired = key(Instant.parse("2026-10-28T23:59:59Z"));
		KeyState expiresToday = key(Instant.parse("2026-10-29T00:00:00Z"));
		KeyRingState ring = new KeyRingState(expired.fingerprint(), "",
			List.of(expired, expiresToday), RevocationCertificate.ABSENT);

		String report = ReleaseKeyStatusCommand.readable(directory, List.of(ring),
			LocalDate.parse("2026-10-29"));

		assertTrue(report.contains("expires expired 2026-10-28"), report);
		assertTrue(report.contains("expires 2026-10-29"), report);
	}

	private static KeyState key(final Instant expires)
	{
		return new KeyState("5B2FA6B11E298BC09287F423D8C403518C49CA75", true, "rsa2048", "SC",
			Instant.parse("2016-05-01T12:56:24Z"), expires, SecretPart.OFFLINE);
	}

	@Test
	@DisplayName("release-key without a subcommand shows its usage")
	void releaseKey_withoutASubcommand_showsItsUsage()
	{
		assertEquals(0, run("release-key"));

		assertTrue(out.contains("status"), out);
	}
}
