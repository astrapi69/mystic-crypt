/**
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
package de.alpharogroup.crypto.blockchain;

import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

import de.alpharogroup.crypto.algorithm.HashAlgorithm;
import de.alpharogroup.crypto.blockchain.api.IBlock;
import de.alpharogroup.crypto.blockchain.api.ITransaction;
import de.alpharogroup.crypto.hash.HashExtensions;
import lombok.AccessLevel;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.FieldDefaults;

/**
 * The class {@link Block}
 */
@Getter
@Setter
@EqualsAndHashCode
@NoArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)
public class Block implements IBlock
{

	byte[] hash;

	byte[] merkleRoot;

	byte[] previousBlockHash;

	long timestamp;

	List<ITransaction> transactions;

	long tries;

	public Block(byte[] previousBlockHash, List<ITransaction> transactions, long tries)
	{
		this.previousBlockHash = previousBlockHash;
		this.transactions = transactions;
		this.tries = tries;
		this.timestamp = System.currentTimeMillis();
		this.merkleRoot = HashExtensions.getMerkleRootHash(
			new LinkedList<>(
				transactions.stream().map(ITransaction::getHash).collect(Collectors.toList())),
			HashAlgorithm.SHA256);
		this.hash = HashExtensions.hash(previousBlockHash, merkleRoot, tries, timestamp,
			HashAlgorithm.SHA256);
	}

	@Override
	public int getLeadingZerosCount()
	{
		for (int i = 0; i < getHash().length; i++)
		{
			if (getHash()[i] != 0)
			{
				return i;
			}
		}
		return getHash().length;
	}


}
