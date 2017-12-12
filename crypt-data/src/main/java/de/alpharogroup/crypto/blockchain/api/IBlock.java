package de.alpharogroup.crypto.blockchain.api;

import java.util.List;

public interface IBlock
{

	byte[] getHash();

	void setHash(byte[] hash);

	byte[] getPreviousBlockHash();

	void setPreviousBlockHash(byte[] previousBlockHash);

	List<ITransaction> getTransactions();

	void setTransactions(List<ITransaction> transactions);

	byte[] getMerkleRoot();

	void setMerkleRoot(byte[] merkleRoot);

	long getTries();

	void setTries(long tries);

	long getTimestamp();

	void setTimestamp(long timestamp);

	byte[] calculateHash();

	byte[] calculateMerkleRoot();

	int getLeadingZerosCount();

}