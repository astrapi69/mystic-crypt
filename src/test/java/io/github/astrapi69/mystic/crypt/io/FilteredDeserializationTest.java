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
package io.github.astrapi69.mystic.crypt.io;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InvalidClassException;
import java.io.InvalidObjectException;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serial;
import java.io.Serializable;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import io.github.astrapi69.crypt.data.model.AesRsaCryptModel;

/**
 * Deserialization through an allow-list: only the named types are built, and limits bound depth,
 * references, array length and stream size. The crafted inputs here are harmless - a type that
 * records whether it was built, a deep but empty nesting, an array that claims a length it does not
 * have - and nothing in them executes anything.
 */
class FilteredDeserializationTest
{

	/** Set when an instance of {@link Tripwire} is read back; it must never be */
	static volatile boolean tripped;

	/** A type outside every allow-list here, which notes that it was built */
	static class Tripwire implements Serializable
	{
		@Serial
		private static final long serialVersionUID = 1L;

		@Serial
		private void readObject(final ObjectInputStream in)
			throws IOException, ClassNotFoundException
		{
			in.defaultReadObject();
			tripped = true;
		}
	}

	private static byte[] serialized(final Object object) throws IOException
	{
		ByteArrayOutputStream bytes = new ByteArrayOutputStream();
		try (ObjectOutputStream out = new ObjectOutputStream(bytes))
		{
			out.writeObject(object);
		}
		return bytes.toByteArray();
	}

	@Test
	@DisplayName("an allowed type is read back unchanged")
	void deserialize_anAllowedType_isReadBack() throws Exception
	{
		AesRsaCryptModel envelope = AesRsaCryptModel.builder().encryptedKey(new byte[] { 1, 2 })
			.symmetricKeyEncryptedObject(new byte[] { 3, 4, 5 }).build();

		AesRsaCryptModel read = FilteredDeserialization.deserialize(serialized(envelope),
			AesRsaCryptModel.class,
			FilteredDeserialization.allowing(List.of(AesRsaCryptModel.class, byte[].class)));

		assertArrayEquals(envelope.getEncryptedKey(), read.getEncryptedKey());
		assertArrayEquals(envelope.getSymmetricKeyEncryptedObject(),
			read.getSymmetricKeyEncryptedObject());
	}

	@Test
	@DisplayName("a type outside the allow-list is refused before it is built")
	void deserialize_aForeignType_isRefusedBeforeItIsBuilt() throws Exception
	{
		tripped = false;
		byte[] foreign = serialized(new Tripwire());

		assertThrows(InvalidClassException.class, () -> FilteredDeserialization.deserialize(foreign,
			String.class, FilteredDeserialization.allowing(List.of(String.class))));

		assertFalse(tripped, "the foreign type was built");
	}

	@Test
	@DisplayName("an allowed type in place of the expected one is refused as well")
	void deserialize_anotherAllowedType_isRefused() throws Exception
	{
		byte[] text = serialized("text");

		InvalidObjectException refused = assertThrows(InvalidObjectException.class,
			() -> FilteredDeserialization.deserialize(text, AesRsaCryptModel.class,
				FilteredDeserialization.allowing(List.of(AesRsaCryptModel.class, String.class))));

		assertTrue(refused.getMessage().contains(AesRsaCryptModel.class.getName()),
			refused.getMessage());
	}

	@Test
	@DisplayName("a deep nesting of empty lists, harmless in itself, is refused at the depth limit")
	void deserialize_aDeepNesting_isRefusedAtTheDepthLimit() throws Exception
	{
		byte[] nested = serialized(nestedLists((int)FilteredDeserialization.MAXIMUM_DEPTH + 10));

		assertThrows(InvalidClassException.class,
			() -> FilteredDeserialization.deserialize(nested, ArrayList.class,
				FilteredDeserialization.allowing(List.of(ArrayList.class, Object[].class))));
	}

	@Test
	@DisplayName("without a filter, the same kind of nesting made deep enough overflows the stack of whoever reads it")
	void plainStream_aVeryDeepNesting_overflowsTheStack() throws Exception
	{
		byte[] nested = serializedOnABigStack(nestedLists(200_000));

		assertThrows(StackOverflowError.class, () -> {
			try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(nested)))
			{
				in.readObject();
			}
		});
		assertThrows(InvalidClassException.class,
			() -> FilteredDeserialization.deserialize(nested, ArrayList.class,
				FilteredDeserialization.allowing(List.of(ArrayList.class, Object[].class))));
	}

	@Test
	@DisplayName("an array that claims a length it does not have exhausts the memory of a plain stream, and is refused by the filter")
	void anArrayClaimingAHugeLength_exhaustsMemory_withoutTheFilter() throws Exception
	{
		byte[] claim = claimingLength(serialized(new long[1]), 1_500_000_000);

		assertThrows(OutOfMemoryError.class, () -> {
			try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(claim)))
			{
				in.readObject();
			}
		});
		assertThrows(InvalidClassException.class, () -> FilteredDeserialization.deserialize(claim,
			long[].class, FilteredDeserialization.allowing(List.of(long[].class))));
	}

	/** How far a stream reaches: the largest depth, reference count and size a filter saw */
	record Reach(long depth, long references, long streamBytes) {
	}

	/** Reads the bytes with a filter that admits everything and notes how far the stream got */
	private static Reach reachOf(final byte[] bytes) throws Exception
	{
		long[] largest = new long[3];
		try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(bytes)))
		{
			in.setObjectInputFilter(info -> {
				largest[0] = Math.max(largest[0], info.depth());
				largest[1] = Math.max(largest[1], info.references());
				largest[2] = Math.max(largest[2], info.streamBytes());
				return ObjectInputFilter.Status.ALLOWED;
			});
			in.readObject();
		}
		return new Reach(largest[0], largest[1], largest[2]);
	}

	@Test
	@DisplayName("a nesting exactly as deep as the limit is still read")
	void deserialize_aNestingAtTheDepthLimit_isRead() throws Exception
	{
		int levels = 1;
		byte[] nested = serialized(nestedLists(levels));
		while (reachOf(nested).depth() < FilteredDeserialization.MAXIMUM_DEPTH)
		{
			nested = serialized(nestedLists(++levels));
		}
		assertEquals(FilteredDeserialization.MAXIMUM_DEPTH, reachOf(nested).depth(),
			"precondition: the nesting reaches the limit exactly");

		assertEquals(nestedLists(levels),
			FilteredDeserialization.deserialize(nested, ArrayList.class,
				FilteredDeserialization.allowing(List.of(ArrayList.class, Object[].class))));
	}

	@Test
	@DisplayName("a stream with exactly as many references as the limit is still read")
	void deserialize_aStreamAtTheReferenceLimit_isRead() throws Exception
	{
		long overhead = reachOf(serialized(dates(100))).references() - 100;
		ArrayList<Object> atTheLimit = dates(
			(int)(FilteredDeserialization.MAXIMUM_REFERENCES - overhead));
		byte[] bytes = serialized(atTheLimit);
		assertEquals(FilteredDeserialization.MAXIMUM_REFERENCES, reachOf(bytes).references(),
			"precondition: the stream reaches the limit exactly");

		assertEquals(atTheLimit,
			FilteredDeserialization.deserialize(bytes, ArrayList.class, FilteredDeserialization
				.allowing(List.of(ArrayList.class, Object[].class, java.util.Date.class))));
	}

	@Test
	@DisplayName("a stream exactly as long as the size limit is still read")
	void deserialize_aStreamAtTheSizeLimit_isRead() throws Exception
	{
		ArrayList<Object> some = dates(50);
		byte[] bytes = serialized(some);
		long size = reachOf(bytes).streamBytes();

		assertEquals(some,
			FilteredDeserialization.deserialize(bytes, ArrayList.class, FilteredDeserialization
				.allowing(List.of(ArrayList.class, Object[].class, java.util.Date.class), size)));
	}

	@Test
	@DisplayName("an array exactly as long as the length limit passes the filter")
	void anArrayAtTheLengthLimit_passesTheFilter() throws Exception
	{
		byte[] oneByte = serialized(new byte[1]);
		byte[] claim = oneByte.clone();
		ByteBuffer.wrap(claim).putInt(claim.length - 1 - Integer.BYTES,
			(int)FilteredDeserialization.MAXIMUM_ARRAY_LENGTH);

		IOException failed = assertThrows(IOException.class,
			() -> FilteredDeserialization.deserialize(claim, byte[].class,
				FilteredDeserialization.allowing(List.of(byte[].class))));

		assertFalse(failed instanceof InvalidClassException,
			"the filter let the array through; the stream then ran out of bytes: " + failed);
	}

	private static ArrayList<Object> dates(final int count)
	{
		ArrayList<Object> dates = new ArrayList<>();
		for (int index = 0; index < count; index++)
		{
			dates.add(new java.util.Date(index));
		}
		return dates;
	}

	@Test
	@DisplayName("a stream with more objects than the reference limit is refused")
	void deserialize_moreObjectsThanTheReferenceLimit_isRefused() throws Exception
	{
		ArrayList<Object> many = new ArrayList<>();
		for (int index = 0; index <= FilteredDeserialization.MAXIMUM_REFERENCES; index++)
		{
			many.add(new java.util.Date(index));
		}
		byte[] crowded = serialized(many);

		assertThrows(InvalidClassException.class,
			() -> FilteredDeserialization.deserialize(crowded, ArrayList.class,
				FilteredDeserialization
					.allowing(List.of(ArrayList.class, Object[].class, java.util.Date.class))));
	}

	@Test
	@DisplayName("a stream that goes on past the size limit is refused at the next object")
	void deserialize_aStreamOverTheSizeLimit_isRefused() throws Exception
	{
		ArrayList<Object> many = new ArrayList<>();
		for (int index = 0; index < 500; index++)
		{
			many.add(new java.util.Date(index));
		}
		byte[] big = serialized(many);

		assertThrows(InvalidClassException.class,
			() -> FilteredDeserialization.deserialize(big, ArrayList.class, FilteredDeserialization
				.allowing(List.of(ArrayList.class, Object[].class, java.util.Date.class), 1024)));
		assertEquals(many,
			FilteredDeserialization.deserialize(big, ArrayList.class, FilteredDeserialization
				.allowing(List.of(ArrayList.class, Object[].class, java.util.Date.class))));
	}

	@Test
	@DisplayName("an allowed array type longer than the array limit is refused before it is allocated")
	void deserialize_anArrayOverTheLengthLimit_isRefused() throws Exception
	{
		byte[] claim = claimingLength(serialized(new long[1]),
			(int)FilteredDeserialization.MAXIMUM_ARRAY_LENGTH + 1);

		assertThrows(InvalidClassException.class, () -> FilteredDeserialization.deserialize(claim,
			long[].class, FilteredDeserialization.allowing(List.of(long[].class))));
	}

	@Test
	@DisplayName("the filter is the stream's own: a plain stream next to it still reads anything")
	void theFilter_isSetOnTheStream_notGlobally() throws Exception
	{
		FilteredDeserialization.allowing(List.of(String.class));

		try (ObjectInputStream in = new ObjectInputStream(
			new ByteArrayInputStream(serialized(new ArrayList<>(List.of("a"))))))
		{
			assertEquals(List.of("a"), in.readObject());
		}
	}

	private static Object nestedLists(final int depth)
	{
		ArrayList<Object> outermost = new ArrayList<>();
		ArrayList<Object> current = outermost;
		for (int level = 1; level < depth; level++)
		{
			ArrayList<Object> next = new ArrayList<>();
			current.add(next);
			current = next;
		}
		return outermost;
	}

	/** Writing a very deep nesting recurses as deeply as reading it, so it gets a big stack */
	private static byte[] serializedOnABigStack(final Object object) throws Exception
	{
		AtomicReference<byte[]> written = new AtomicReference<>();
		AtomicReference<Exception> failed = new AtomicReference<>();
		Thread writer = new Thread(null, () -> {
			try
			{
				written.set(serialized(object));
			}
			catch (IOException exception)
			{
				failed.set(exception);
			}
		}, "big-stack-writer", 1L << 30);
		writer.start();
		writer.join();
		if (failed.get() != null)
		{
			throw failed.get();
		}
		return written.get();
	}

	/**
	 * The serialized one-element array with its length field changed: the stream then claims far
	 * more elements than it carries
	 */
	private static byte[] claimingLength(final byte[] oneElementArray, final int length)
	{
		byte[] claim = oneElementArray.clone();
		ByteBuffer.wrap(claim).putInt(claim.length - Long.BYTES - Integer.BYTES, length);
		return claim;
	}
}
