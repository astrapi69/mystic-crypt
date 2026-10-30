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
package io.github.astrapi69.mystic.crypt;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.util.Properties;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

import io.github.astrapi69.mystic.crypt.cli.MysticCryptCli;
import picocli.CommandLine;

/**
 * Checks that what the README and the project page tell a reader matches the code: the latest
 * release version, the Maven coordinates and the names of the command line commands (#223).
 * <p>
 * The release version is the first version heading of the changelog that is not marked unreleased.
 * The coordinates are {@code groupPackage} from {@code gradle.properties} and
 * {@code rootProject.name} from {@code settings.gradle}. The commands are the subcommands picocli
 * registers on {@link MysticCryptCli}.
 * <p>
 * The project page lives on the {@code gh-pages} branch. CI checks that branch out and passes its
 * {@code index.html} as {@code PAGES_INDEX}; where that is missing in CI the test fails, and
 * locally it is skipped with that reason.
 */
class ReleaseConsistencyTest
{

	private static final Path README = Path.of("README.md");

	private static final Path CHANGELOG = Path.of("CHANGELOG.md");

	private static final Path GRADLE_PROPERTIES = Path.of("gradle.properties");

	private static final Path SETTINGS = Path.of("settings.gradle");

	/**
	 * picocli's own help subcommand. It is not a function of the library (library-first.md), so the
	 * command table does not list it and the comparison leaves it out.
	 */
	private static final String PICOCLI_HELP = "help";

	private static final String SEARCH_CONSOLE_FILE = "google5bee4cd8b72b08de.html";

	private static final String PAGE_ADDRESS = "https://astrapi69.github.io/mystic-crypt/";

	private static final Pattern LASTMOD = Pattern
		.compile("<lastmod>(\\d{4}-\\d{2}-\\d{2})</lastmod>");

	private static final Pattern RELEASE_HEADING = Pattern.compile("^Version (\\d+(?:\\.\\d+)+)$",
		Pattern.MULTILINE);

	private static final Pattern ARTIFACT_NAME = Pattern
		.compile("rootProject\\.name\\s*=\\s*'([^']+)'");

	private static final Pattern CODE_NAME = Pattern.compile("`([a-z][a-z0-9-]*)`");

	private static final Pattern PAGE_CODE_NAME = Pattern.compile("<code>([a-z][a-z0-9-]*)</code>");

	private static final Pattern PAGE_TABLE_ROW = Pattern.compile("<tr><td>(.*?)</td>");

	@Test
	void readme_namesTheLatestReleaseAndHasNoPlaceholder() throws IOException
	{
		String readme = Files.readString(README);

		assertFalse(readme.contains("${latestVersion}"),
			"README still has the ${latestVersion} placeholder");
		assertTrue(readme.contains(coordinates() + ":" + latestReleaseVersion()),
			"README does not name " + coordinates() + ":" + latestReleaseVersion());
		assertTrue(readme.contains("mystic-crypt-" + latestReleaseVersion() + "-all.jar"),
			"README does not name the -all jar of " + latestReleaseVersion());
	}

	@Test
	void readme_commandTableMatchesTheRegisteredCommands() throws IOException
	{
		assertNoDifference("README command table", registeredCommands(),
			readmeCommands(Files.readString(README)));
	}

	@Test
	void projectPage_namesTheLatestReleaseAndHasNoPlaceholder() throws IOException
	{
		String page = unescapeMarkup(Files.readString(pagesIndex()));

		assertFalse(page.contains("${latestVersion}"),
			"project page still has the ${latestVersion} placeholder");
		assertTrue(page.contains("Current release " + latestReleaseVersion() + " "),
			"project page does not say: Current release " + latestReleaseVersion());
		assertTrue(page.contains(coordinates() + ":" + latestReleaseVersion()),
			"project page does not name " + coordinates() + ":" + latestReleaseVersion());
		assertTrue(page.contains("<version>" + latestReleaseVersion() + "</version>"),
			"project page does not give the Maven version " + latestReleaseVersion());
	}

	/**
	 * The Search Console ownership file must stay on the page's branch. Removing it withdraws the
	 * verification that Google granted.
	 */
	@Test
	void projectPage_keepsTheSearchConsoleVerificationFile() throws IOException
	{
		Path verification = pagesIndex().resolveSibling(SEARCH_CONSOLE_FILE);

		assertTrue(Files.isRegularFile(verification), SEARCH_CONSOLE_FILE
			+ " is missing from the project page: Search Console would lose " + "its verification");
		assertEquals("google-site-verification: " + SEARCH_CONSOLE_FILE,
			Files.readString(verification).strip(),
			SEARCH_CONSOLE_FILE + " does not carry the verification line");
	}

	/** The sitemap lists the page's address, with a lastmod date that is a calendar date. */
	@Test
	void projectPage_hasASitemapWithADatedEntry() throws IOException
	{
		Path sitemap = pagesIndex().resolveSibling("sitemap.xml");
		assertTrue(Files.isRegularFile(sitemap), "sitemap.xml is missing from the project page");
		String xml = Files.readString(sitemap);

		assertTrue(xml.contains("<loc>" + PAGE_ADDRESS + "</loc>"),
			"sitemap.xml does not list " + PAGE_ADDRESS);
		Matcher lastmod = LASTMOD.matcher(xml);
		assertTrue(lastmod.find(), "sitemap.xml has no lastmod date");
		LocalDate.parse(lastmod.group(1));
	}

	@Test
	void projectPage_commandTableMatchesTheRegisteredCommands() throws IOException
	{
		String page = unescapeMarkup(Files.readString(pagesIndex()));

		assertNoDifference("project page command table", registeredCommands(), pageCommands(page));
	}

	@Test
	void assertNoDifference_namesTheMissingCommand()
	{
		Set<String> registered = Set.of("hash", "keygen");

		AssertionError failure = assertThrows(AssertionError.class,
			() -> assertNoDifference("table", registered, Set.of("hash")));

		assertTrue(failure.getMessage().contains("missing [keygen]"), failure.getMessage());
	}

	@Test
	void assertNoDifference_namesTheCommandThatIsNotRegistered()
	{
		Set<String> registered = Set.of("hash");

		AssertionError failure = assertThrows(AssertionError.class,
			() -> assertNoDifference("table", registered, Set.of("hash", "obfuscate")));

		assertTrue(failure.getMessage().contains("not registered [obfuscate]"),
			failure.getMessage());
	}

	@Test
	void assertNoDifference_acceptsEqualSets()
	{
		assertNoDifference("table", Set.of("hash", "keygen"), Set.of("keygen", "hash"));
	}

	/** The release version: the first changelog heading that is not marked unreleased. */
	static String latestReleaseVersion() throws IOException
	{
		Matcher heading = RELEASE_HEADING.matcher(Files.readString(CHANGELOG));
		assertTrue(heading.find(), "CHANGELOG has no released version heading");
		return heading.group(1);
	}

	/** The Maven group and artifact, as the build publishes them. */
	static String coordinates() throws IOException
	{
		Properties properties = new Properties();
		try (InputStream in = Files.newInputStream(GRADLE_PROPERTIES))
		{
			properties.load(in);
		}
		Matcher artifact = ARTIFACT_NAME.matcher(Files.readString(SETTINGS));
		assertTrue(artifact.find(), "settings.gradle names no rootProject.name");
		return properties.getProperty("groupPackage") + ":" + artifact.group(1);
	}

	/** Every command picocli registers on the root command, except the help subcommand. */
	static Set<String> registeredCommands()
	{
		Set<String> names = new TreeSet<>(
			new CommandLine(MysticCryptCli.class).getSubcommands().keySet());
		names.remove(PICOCLI_HELP);
		return names;
	}

	/** The command names in the table of the README's command-line section. */
	static Set<String> readmeCommands(String readme)
	{
		String section = readme.substring(readme.indexOf("## Command-line interface"));
		int next = section.indexOf("\n## ", 1);
		if (next > 0)
		{
			section = section.substring(0, next);
		}
		Set<String> names = new TreeSet<>();
		for (String line : section.split("\n"))
		{
			if (line.startsWith("| `"))
			{
				String firstCell = line.substring(1, line.indexOf('|', 1));
				Matcher code = CODE_NAME.matcher(firstCell);
				while (code.find())
				{
					names.add(code.group(1));
				}
			}
		}
		return names;
	}

	/**
	 * The page writes its code samples with escaped angle brackets, so {@code <version>} reads as
	 * {@code &lt;version&gt;}. The checks compare the text a reader sees.
	 */
	static String unescapeMarkup(String html)
	{
		return html.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&");
	}

	/** The command names in the table of the project page's command-line section. */
	static Set<String> pageCommands(String page)
	{
		int start = page.indexOf("<section id=\"cli\">");
		int end = page.indexOf("</section>", start);
		assertTrue(start >= 0 && end > start, "project page has no cli section");
		Matcher row = PAGE_TABLE_ROW.matcher(page.substring(start, end));
		Set<String> names = new TreeSet<>();
		while (row.find())
		{
			Matcher code = PAGE_CODE_NAME.matcher(row.group(1));
			while (code.find())
			{
				names.add(code.group(1));
			}
		}
		return names;
	}

	/**
	 * The page on the gh-pages branch, as {@code PAGES_INDEX} names it. Without it outside CI the
	 * test is skipped; in CI a missing value fails the build, so the page cannot go unchecked.
	 */
	static Path pagesIndex()
	{
		String configured = System.getProperty("mysticcrypt.pagesIndex", "");
		if (configured.isEmpty())
		{
			if (System.getenv("CI") != null)
			{
				fail("PAGES_INDEX is not set in CI: the project page would go unchecked");
			}
			assumeTrue(false,
				"PAGES_INDEX is not set: the page is checked in CI, where gh-pages is "
					+ "checked out");
		}
		Path page = Path.of(configured);
		assertTrue(Files.isRegularFile(page), "PAGES_INDEX names no file: " + page);
		return page;
	}

	static void assertNoDifference(String what, Set<String> registered, Set<String> documented)
	{
		Set<String> missing = new TreeSet<>(registered);
		missing.removeAll(documented);
		Set<String> notRegistered = new TreeSet<>(documented);
		notRegistered.removeAll(registered);
		assertTrue(missing.isEmpty() && notRegistered.isEmpty(),
			what + " differs from the registered commands: missing " + missing + ", not registered "
				+ notRegistered);
	}
}
