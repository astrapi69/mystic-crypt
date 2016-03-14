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

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import de.alpharogroup.crypto.interfaces.GenericDecryptor;

/**
 * The Class CryptoOutputStream.
 *
 * @version 1.0
 *
 * @author Asterios Raptis
 *
 */
public class CryptoOutputStream extends FilterOutputStream
{
	private final GenericDecryptor<Integer, Integer> decryptor;

	public CryptoOutputStream(final OutputStream out, final GenericDecryptor<Integer, Integer> decryptor)
	{
		super(out);
		this.decryptor = decryptor;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @see java.io.OutputStream#write(int)
	 */
	@Override
	public void write(final int b) throws IOException
	{
		try
		{
			final Integer dba = this.decryptor.decrypt(b);
			out.write(dba);
		}
		catch (final Exception e1)
		{
			throw new RuntimeException(e1);
		}
	}

}
