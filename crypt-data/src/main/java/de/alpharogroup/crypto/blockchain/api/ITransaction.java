package de.alpharogroup.crypto.blockchain.api;

public interface ITransaction
{

	byte[] getHash();

	void setHash(byte[] hash);

	String getText();

	void setText(String text);

	byte[] getSenderHash();

	void setSenderHash(byte[] senderHash);

	byte[] getSignature();

	void setSignature(byte[] signature);

	long getTimestamp();

	void setTimestamp(long timestamp);

	byte[] getSignableData();

	byte[] calculateHash();

}