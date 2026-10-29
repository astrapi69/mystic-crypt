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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InvalidObjectException;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;
import java.util.Collection;
import java.util.Set;

/**
 * Java deserialization through an allow-list. A plain {@link ObjectInputStream} builds whatever
 * class the bytes name, as long as it is on the class path, so whoever supplies the bytes chooses
 * the code that runs while they are read. The filter here admits exactly the named classes and
 * bounds depth, references, array length and stream size, and it is set on the one stream it reads,
 * never JVM-wide.
 */
public final class FilteredDeserialization
{

	/** How deep a stream may nest; the formats read here are two or three levels deep */
	public static final long MAXIMUM_DEPTH = 16;

	/** How many objects and references a stream may hold */
	public static final long MAXIMUM_REFERENCES = 10_000;

	/** The longest array a stream may declare, in elements: a 64 MiB byte array */
	public static final long MAXIMUM_ARRAY_LENGTH = 64L * 1024 * 1024;

	/** The most bytes a stream may consume */
	public static final long MAXIMUM_STREAM_BYTES = 2 * MAXIMUM_ARRAY_LENGTH;

	private FilteredDeserialization()
	{
	}

	/**
	 * A filter that admits exactly the given classes - not their subclasses, not the classes their
	 * fields name - within the default limits
	 *
	 * @param allowed
	 *            the classes a stream may hold, array classes included, for example
	 *            {@code byte[].class}
	 * @return the filter
	 */
	public static ObjectInputFilter allowing(final Collection<Class<?>> allowed)
	{
		return allowing(allowed, MAXIMUM_STREAM_BYTES);
	}

	/**
	 * A filter that admits exactly the given classes, with a limit of its own for the stream size
	 *
	 * @param allowed
	 *            the classes a stream may hold, array classes included
	 * @param maximumStreamBytes
	 *            the most bytes a stream may consume
	 * @return the filter
	 */
	public static ObjectInputFilter allowing(final Collection<Class<?>> allowed,
		final long maximumStreamBytes)
	{
		Set<Class<?>> classes = Set.copyOf(allowed);
		return info -> {
			if (info.depth() > MAXIMUM_DEPTH || info.references() > MAXIMUM_REFERENCES
				|| info.arrayLength() > MAXIMUM_ARRAY_LENGTH
				|| info.streamBytes() > maximumStreamBytes)
			{
				return ObjectInputFilter.Status.REJECTED;
			}
			Class<?> serialClass = info.serialClass();
			return serialClass == null || classes.contains(serialClass)
				? ObjectInputFilter.Status.ALLOWED
				: ObjectInputFilter.Status.REJECTED;
		};
	}

	/**
	 * Reads one object of the expected type from the given bytes through the given filter
	 *
	 * @param <T>
	 *            the expected type
	 * @param bytes
	 *            the serialized object
	 * @param expected
	 *            the type the object must have
	 * @param filter
	 *            the filter the stream reads through
	 * @return the object
	 * @throws java.io.InvalidClassException
	 *             when the filter refuses a class or a limit
	 * @throws InvalidObjectException
	 *             when the stream holds an allowed object of another type than the expected one
	 * @throws IOException
	 *             when the bytes are not a serialized object
	 * @throws ClassNotFoundException
	 *             when an allowed class is not on the class path
	 */
	public static <T> T deserialize(final byte[] bytes, final Class<T> expected,
		final ObjectInputFilter filter) throws IOException, ClassNotFoundException
	{
		try (ObjectInputStream in = open(new ByteArrayInputStream(bytes), filter))
		{
			Object object = in.readObject();
			if (!expected.isInstance(object))
			{
				throw new InvalidObjectException("expected a " + expected.getName()
					+ " but the stream holds a " + object.getClass().getName());
			}
			return expected.cast(object);
		}
	}

	/**
	 * Opens an object stream that reads through the given filter
	 *
	 * @param in
	 *            the bytes to read
	 * @param filter
	 *            the filter, set on this stream only
	 * @return the stream
	 * @throws IOException
	 *             when the stream header cannot be read
	 */
	public static ObjectInputStream open(final InputStream in, final ObjectInputFilter filter)
		throws IOException
	{
		ObjectInputStream objects = new ObjectInputStream(in);
		objects.setObjectInputFilter(filter);
		return objects;
	}
}
