package de.alpharogroup.crypto.blockchain.api;

import java.util.List;

import de.alpharogroup.crypto.blockchain.Transaction;

public interface IBlock
{

	byte[] getHash();

	void setHash(byte[] hash);

	byte[] getPreviousBlockHash();

	void setPreviousBlockHash(byte[] previousBlockHash);

	List<Transaction> getTransactions();

	void setTransactions(List<Transaction> transactions);

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