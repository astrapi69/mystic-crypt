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
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

/**
 * Keeps, for the report of a failed GnuPG test, what a read of a home met: the key files the home
 * held and what {@link SecretKeyFiles} said about them while it read (#309).
 * <p>
 * The reader logs a key file it cannot read, with the file and the reason, and then reports every
 * key without a key file of its own as {@link SecretPart#UNKNOWN} instead of
 * {@link SecretPart#OFFLINE}. A PIT coverage run shows neither that log nor a test's assertion
 * message, so the diagnosis is recorded at the moment of reading and written to a file when a test
 * fails.
 */
final class ReadingDiagnosis
{

	private ReadingDiagnosis()
	{
	}

	/**
	 * A read that throws only what reading a home throws
	 *
	 * @param <T>
	 *            what the read returns
	 */
	@FunctionalInterface
	interface Read<T>
	{
		/**
		 * Reads
		 *
		 * @return what was read
		 */
		T read() throws IOException;
	}

	/**
	 * What one read returned, and the diagnosis taken while it ran
	 *
	 * @param <T>
	 *            what the read returns
	 * @param result
	 *            what the read returned
	 * @param diagnosis
	 *            the key files of the home and what the reader logged, as text
	 */
	record Recorded<T> (T result, String diagnosis) {
	}

	/**
	 * Runs the read, listening to what {@link SecretKeyFiles} logs meanwhile, and describes the key
	 * files of the home as they were when the read ended
	 *
	 * @param <T>
	 *            what the read returns
	 * @param home
	 *            the GnuPG home that is read
	 * @param read
	 *            the read
	 * @return the result and the diagnosis
	 */
	static <T> Recorded<T> record(final Path home, final Read<T> read) throws IOException
	{
		Logger logger = Logger.getLogger(SecretKeyFiles.class.getName());
		List<String> said = Collections.synchronizedList(new ArrayList<>());
		Handler listener = new Handler()
		{
			@Override
			public void publish(final LogRecord logged)
			{
				said.add(logged.getLevel() + " " + logged.getMessage()
					+ (logged.getThrown() == null ? "" : ": " + logged.getThrown()));
			}

			@Override
			public void flush()
			{
			}

			@Override
			public void close()
			{
			}
		};
		logger.addHandler(listener);
		try
		{
			T result = read.read();
			return new Recorded<>(result, keyFiles(home) + whatTheReaderSaid(said));
		}
		finally
		{
			logger.removeHandler(listener);
		}
	}

	/**
	 * The key files of the home as they are now: name and size of each, in name order
	 *
	 * @param home
	 *            the GnuPG home
	 * @return one line per key file, or a line saying there is no key directory
	 */
	static String keyFiles(final Path home) throws IOException
	{
		Path keys = home.resolve(GnuPgHome.PRIVATE_KEYS);
		if (!Files.isDirectory(keys))
		{
			return "no " + GnuPgHome.PRIVATE_KEYS + " in " + home + "\n";
		}
		List<String> lines = new ArrayList<>();
		try (DirectoryStream<Path> files = Files.newDirectoryStream(keys))
		{
			for (Path file : files)
			{
				lines.add(file.getFileName() + ", " + Files.size(file) + " bytes");
			}
		}
		Collections.sort(lines);
		return GnuPgHome.PRIVATE_KEYS + ": " + lines.size() + " files\n" + String.join("\n", lines)
			+ "\n";
	}

	private static String whatTheReaderSaid(final List<String> said)
	{
		synchronized (said)
		{
			return said.isEmpty()
				? "the reader logged nothing\n"
				: "the reader logged:\n" + String.join("\n", said) + "\n";
		}
	}
}
