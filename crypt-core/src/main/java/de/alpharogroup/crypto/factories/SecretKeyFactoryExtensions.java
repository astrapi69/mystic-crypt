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
package de.alpharogroup.crypto.factories;

import java.security.NoSuchAlgorithmException;

import javax.crypto.SecretKeyFactory;


/**
 * A factory for creating SecretKeyFactory objects.
 */
public class SecretKeyFactoryExtensions
{


	/**
	 * Factory method for creating a new {@link SecretKeyFactory} from the given algorithm.
	 *
	 * @param algorithm            the algorithm
	 * @return the new {@link SecretKeyFactory} from the given algorithm.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 */
	public static SecretKeyFactory newSecretKeyFactory(final String algorithm) throws NoSuchAlgorithmException {
		final SecretKeyFactory factory = SecretKeyFactory.getInstance(algorithm);
		return factory;
	}
}
