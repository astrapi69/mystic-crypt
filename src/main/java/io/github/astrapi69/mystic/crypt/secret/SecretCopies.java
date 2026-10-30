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

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

import javax.crypto.spec.PBEKeySpec;

/**
 * Holds the copies of secret material a method makes on its way - the characters of a passphrase,
 * derived key bytes, the buffers of a charset coder, a key spec - and overwrites every one of them
 * when it is closed:
 *
 * <pre>
 * try (SecretCopies copies = SecretCopies.open())
 * {
 * 	byte[] keyBytes = copies.hold(derived.getEncoded());
 * 	return new SecretKeySpec(keyBytes, "AES");
 * }
 * </pre>
 *
 * A copy that never leaves the method cannot be read by a test through the method's result, and
 * without its wipe the secret stays in memory longer - a change of behaviour no assertion on the
 * result can see. So every copy goes through here, and after the wipe a test can look at each one
 * (#227).
 */
public final class SecretCopies implements AutoCloseable
{

	/**
	 * What a test watches: after closing, every copy is shown to it, already overwritten. Empty
	 * outside a test; package-private, so a test that wants to watch lives in this package
	 */
	static final ThreadLocal<Consumer<Object>> WATCHER = new ThreadLocal<>();

	private final List<Held> held = new ArrayList<>();

	private SecretCopies()
	{
	}

	/**
	 * @return a new, empty holder, to be closed when the method is done with its copies
	 */
	public static SecretCopies open()
	{
		return new SecretCopies();
	}

	/**
	 * Holds a copy of secret bytes until this is closed
	 *
	 * @param copy
	 *            the copy; null is accepted and ignored
	 * @return the same array, to be used
	 */
	public byte[] hold(final byte[] copy)
	{
		return remember(copy, () -> SecretBuffers.wipe(copy));
	}

	/**
	 * Holds a copy of secret characters until this is closed
	 *
	 * @param copy
	 *            the copy; null is accepted and ignored
	 * @return the same array, to be used
	 */
	public char[] hold(final char[] copy)
	{
		return remember(copy, () -> SecretBuffers.wipe(copy));
	}

	/**
	 * Holds a buffer whose backing array holds secret bytes, such as a charset encoder's output
	 *
	 * @param copy
	 *            the buffer; null is accepted and ignored
	 * @return the same buffer, to be used
	 */
	public ByteBuffer hold(final ByteBuffer copy)
	{
		return remember(copy, () -> SecretBuffers.wipeBackingArrayOf(copy));
	}

	/**
	 * Holds a buffer whose backing array holds secret characters, such as a charset decoder's
	 * output
	 *
	 * @param copy
	 *            the buffer; null is accepted and ignored
	 * @return the same buffer, to be used
	 */
	public CharBuffer hold(final CharBuffer copy)
	{
		return remember(copy, () -> SecretBuffers.wipeBackingArrayOf(copy));
	}

	/**
	 * Holds a key spec, whose own copy of the password is cleared on close
	 *
	 * @param copy
	 *            the key spec; null is accepted and ignored
	 * @return the same key spec, to be used
	 */
	public PBEKeySpec hold(final PBEKeySpec copy)
	{
		return remember(copy, () -> copy.clearPassword());
	}

	/**
	 * Overwrites every copy held, then shows each one to a watching test
	 */
	@Override
	public void close()
	{
		held.forEach(copy -> copy.overwrite().run());
		Consumer<Object> watcher = WATCHER.get();
		if (watcher != null)
		{
			held.forEach(copy -> watcher.accept(copy.copy()));
		}
	}

	private <T> T remember(final T copy, final Runnable overwrite)
	{
		if (copy != null)
		{
			held.add(new Held(copy, overwrite));
		}
		return copy;
	}

	/** A copy held, and how it is overwritten: each kind brings its own, so no kind is unknown */
	private record Held(Object copy, Runnable overwrite) {
	}
}
