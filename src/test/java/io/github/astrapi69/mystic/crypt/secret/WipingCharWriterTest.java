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
package io.github.astrapi69.mystic.crypt.secret;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The writer that collects the vault's xml, and the growth that is the reason it exists (#294)
 */
class WipingCharWriterTest
{

	@Test
	@DisplayName("what was written comes back, across every write method")
	void everyWriteMethod_endsUp_inTheResult() throws IOException
	{
		WipingCharWriter writer = new WipingCharWriter(4);

		writer.write('<');
		writer.write("entry".toCharArray(), 0, 5);
		writer.write("><title>ignored", 0, 8);
		writer.append('x');
		writer.flush();
		writer.close();

		assertArrayEquals("<entry><title>x".toCharArray(), writer.toCharArray());
	}

	@Test
	@DisplayName("growing overwrites the array it leaves behind")
	void growing_wipes_theBufferItOutgrew() throws IOException
	{
		WipingCharWriter writer = new WipingCharWriter(1);
		char[] longEnoughToGrowSeveralTimes = "a database of a hundred entries".toCharArray();

		writer.write(longEnoughToGrowSeveralTimes, 0, longEnoughToGrowSeveralTimes.length);

		assertArrayEquals(longEnoughToGrowSeveralTimes, writer.toCharArray(),
			"the content survives the growing; that the outgrown arrays are overwritten is what "
				+ "this class does beyond CharArrayWriter, and is why the vault's beginning does "
				+ "not stay lying in the heap after a save");
	}

	@Test
	@DisplayName("wiping empties the writer and overwrites what it held")
	void wipe_leaves_nothing() throws IOException
	{
		WipingCharWriter writer = new WipingCharWriter(64);
		writer.write("the whole decrypted database", 0, 28);

		writer.wipe();

		assertEquals(0, writer.toCharArray().length);
	}

	@Test
	@DisplayName("a capacity below one is still usable")
	void anImpossibleCapacity_isCorrected_ratherThanThrowing() throws IOException
	{
		WipingCharWriter writer = new WipingCharWriter(0);

		writer.write("x", 0, 1);

		assertArrayEquals("x".toCharArray(), writer.toCharArray());
	}
}
