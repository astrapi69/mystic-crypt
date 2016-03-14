/**
 * Copyright (C) 2007 Asterios Raptis
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.alpharogroup.crypto.io;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

import de.alpharogroup.crypto.interfaces.StreamEncryptor;

/**
 * The Class CryptoInputStream.
 *
 * @version 1.0
 *
 * @author Asterios Raptis
 *
 */
public class CryptoInputStream extends FilterInputStream
{
	private final StreamEncryptor encryptor;

	protected CryptoInputStream(final InputStream in,
		final StreamEncryptor encryptor)
	{
		super(in);
		this.encryptor = encryptor;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @see java.io.InputStream#read()
	 */
	@Override
	public int read() throws IOException
	{
		final int b = in.read();
		if(b  != -1){
			try
			{
				final int encrypt = this.encryptor.encrypt(b);
				return encrypt;
			}
			catch (final Exception e)
			{
				throw new RuntimeException(e);
			}
		}
		return b;

	}

	@Override
	public int read(final byte[] b) throws IOException
	{
		return read(b, 0, b.length);
	}

    @Override
	public int read(final byte[] buf, final int off, int len) throws IOException {
        len = in.read(buf, off, len);
        if (len != -1) {
        	try
			{
        		final int encrypt = this.encryptor.encrypt(len);
				return encrypt;
			}
			catch (final Exception e)
			{
				throw new RuntimeException(e);
			}
        }
        return len;
    }


}
