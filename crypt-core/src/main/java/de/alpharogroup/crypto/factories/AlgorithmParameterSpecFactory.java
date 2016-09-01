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

import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.spec.PBEParameterSpec;

/**
 * A factory for creating AlgorithmParameterSpec objects.
 */
public class AlgorithmParameterSpecFactory
{

	/**
	 * Factory method for creating a new {@link PBEParameterSpec} from the given salt and iteration count.
	 *
	 * @param salt the salt
	 * @param iterationCount the iteration count
	 * @return the new {@link PBEParameterSpec} from the given salt and iteration count.
	 */
	public static AlgorithmParameterSpec newPBEParameterSpec(final byte[] salt,final int iterationCount){
		final AlgorithmParameterSpec paramSpec = new PBEParameterSpec(salt, iterationCount);
		return paramSpec;
	}
}
