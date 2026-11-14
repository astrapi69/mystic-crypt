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
package io.github.astrapi69.mystic.crypt.pw;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;


/**
 * The formats a file sealed with a passphrase comes in across this library family, told apart by
 * their header, and one reader for all of them (#306, astrapi69/mystic-crypt-ui#877).
 * <p>
 * Two writers use {@link PassphraseEnvelope} under markers of their own: {@code encrypt} of this
 * library's command line writes {@code MCFILE}, the file encryption window of mystic-crypt-ui
 * writes {@code MCFILE1}. {@code decrypt} still reads the released layout of
 * {@link PassphraseCryptor}, {@code MCRYPT}. This type writes nothing; which format both sides
 * write is a decision of its own (mystic-crypt-ui#877, stage 2).
 * <p>
 * <b>A header cannot always tell {@code MCFILE1} from {@code MCFILE}.</b> {@code MCFILE1} starts
 * with {@code MCFILE}, and the byte after the {@code MCFILE} marker is the first byte of a random
 * salt, so one {@code MCFILE} in 256 starts with {@code MCFILE1} as well. Read the wrong way, a
 * file's iteration count is taken one byte off - a count of millions or billions, which the key
 * derivation spends minutes on before it fails. Both layouts record their count, so where the
 * header fits both, a reading whose count is above {@link #MOST_BELIEVABLE_ITERATIONS} is not
 * tried. For a file written with today's {@link PassphraseEnvelope#ITERATIONS}, that leaves the
 * right reading, or the right reading first.
 * <p>
 * <b>The caller owns the passphrase array</b>, as with {@link PassphraseEnvelope}: {@link #open}
 * reads it and never modifies it, also for {@code MCRYPT}, whose own reader overwrites the array it
 * is given and is therefore handed a copy, which it zero-fills itself.
 * <p>
 * Which format a header shows is not offered as a method of its own: no caller needs it, and for a
 * header that fits both {@code MCFILE1} and {@code MCFILE} it could not always answer.
 * {@link #open} makes that choice itself and reports only the outcome.
 *
 * @since 13.11
 */
public enum PassphraseFileFormat
{

	/** What {@code encrypt} of this library's command line writes since #160 */
	MCFILE("MCFILE"),

	/** What the file encryption window of mystic-crypt-ui writes, file and text alike */
	MCFILE1("MCFILE1"),

	/**
	 * The released layout of {@link PassphraseCryptor}, which {@code encrypt} wrote before #160 and
	 * lethenon 0.1.0 wrote; read, never written again
	 */
	MCRYPT("MCRYPT");

	/**
	 * The highest iteration count a reading is believed when the header fits two formats: ten times
	 * what is written today. A reading one byte off gives {@code MCFILE1} about 153 million for an
	 * {@code MCFILE} of 600 000, and {@code MCFILE} at least 16 777 216 for an {@code MCFILE1}
	 * whose last salt byte is not 0
	 */
	static final long MOST_BELIEVABLE_ITERATIONS = 10L * PassphraseEnvelope.ITERATIONS;

	/** The markers, the longest first, so that {@code MCFILE1} is looked for before its prefix */
	private static final List<PassphraseFileFormat> BY_MARKER_LENGTH = List.of(MCFILE1, MCFILE,
		MCRYPT);

	private final byte[] magic;

	PassphraseFileFormat(final String marker)
	{
		this.magic = marker.getBytes(StandardCharsets.US_ASCII);
	}

	/**
	 * Opens content in any of the formats, without rewriting it
	 *
	 * @param content
	 *            the sealed bytes
	 * @param passphrase
	 *            the passphrase, read and not modified; the caller overwrites it afterwards
	 * @return the plaintext
	 * @throws IllegalArgumentException
	 *             if the content is in none of the formats, or is cut short behind its marker
	 * @throws SecurityException
	 *             if it is in one of them and does not open: the passphrase is wrong or the data
	 *             was altered. A {@link SecurityException}, not a {@link GeneralSecurityException},
	 *             because {@link PassphraseEnvelope#decrypt(byte[], byte[], char[])} and
	 *             {@link PassphraseCryptor#decrypt(char[], byte[])} already throw it for exactly
	 *             this, and the command line's exit code 1 rests on it
	 * @throws GeneralSecurityException
	 *             if the key cannot be derived
	 * @throws NullPointerException
	 *             if the passphrase is null; the empty passphrase opens what was sealed under it
	 * @since 13.11
	 */
	public static byte[] open(final byte[] content, final char[] passphrase)
		throws GeneralSecurityException
	{
		PassphraseEnvelope.requirePassphraseToOpen(passphrase);
		List<PassphraseFileFormat> readings = readingsOf(content);
		if (readings.isEmpty())
		{
			throw new IllegalArgumentException("this is not a file sealed with a passphrase: "
				+ "the marker is missing, it starts with none of MCFILE, MCFILE1 or MCRYPT");
		}
		RuntimeException refusal = null;
		for (PassphraseFileFormat reading : readings)
		{
			try
			{
				return reading.decrypt(content, passphrase);
			}
			catch (SecurityException | IllegalArgumentException notThisReading)
			{
				// "ours, and it would not open" outranks "cut short", whichever reading said it
				if (!(refusal instanceof SecurityException))
				{
					refusal = notThisReading;
				}
			}
		}
		throw refusal;
	}

	/**
	 * The formats the content can be read as, in the order they are tried: those whose marker it
	 * starts with, the longest marker first, and where that is more than one, only those whose
	 * recorded iteration count can be believed - unless none can, then all of them
	 *
	 * @param content
	 *            the content, or at least its first bytes; may be null
	 * @return the readings, empty when the content starts with none of the markers
	 */
	static List<PassphraseFileFormat> readingsOf(final byte[] content)
	{
		List<PassphraseFileFormat> named = new ArrayList<>();
		for (PassphraseFileFormat format : BY_MARKER_LENGTH)
		{
			if (PassphraseEnvelope.hasMagic(content, format.magic))
			{
				named.add(format);
			}
		}
		if (named.size() < 2)
		{
			return named;
		}
		List<PassphraseFileFormat> believable = new ArrayList<>();
		for (PassphraseFileFormat format : named)
		{
			if (format.recordedIterations(content) <= MOST_BELIEVABLE_ITERATIONS)
			{
				believable.add(format);
			}
		}
		return believable.isEmpty() ? named : believable;
	}

	/**
	 * The iteration count the content records when read as this format, an envelope format: 0 when
	 * the content is too short to say, which leaves the reading to be tried and refused as cut
	 * short
	 */
	private long recordedIterations(final byte[] content)
	{
		if (content.length < PassphraseEnvelope.headerLength(magic))
		{
			return 0;
		}
		return Integer.toUnsignedLong(PassphraseEnvelope.iterationsOf(magic, content));
	}

	private byte[] decrypt(final byte[] content, final char[] passphrase)
		throws GeneralSecurityException
	{
		if (this != MCRYPT)
		{
			return PassphraseEnvelope.decrypt(magic, content, passphrase);
		}
		// PassphraseCryptor overwrites the array it is given, on success and on failure; it gets a
		// copy, which it leaves zero-filled, and the caller's array stays as it was
		return PassphraseCryptor.decrypt(passphrase.clone(), content);
	}
}
