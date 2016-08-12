/**
 * Copyright (C) 2015 Asterios Raptis
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

import java.io.OutputStream;

import javax.crypto.CipherOutputStream;

import de.alpharogroup.crypto.core.BaseDecryptor;

/**
 * The Class CryptoOutputStream.
 *
 * @version 1.0
 *
 * @author Asterios Raptis
 *
 */
public class CryptoOutputStream extends CipherOutputStream
{

	public CryptoOutputStream(final OutputStream out, final BaseDecryptor<?, ?> decryptor)
	{
		super(out, decryptor.getCipher());
	}

}
