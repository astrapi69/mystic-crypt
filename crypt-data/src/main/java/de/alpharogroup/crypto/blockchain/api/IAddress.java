package de.alpharogroup.crypto.blockchain.api;

public interface IAddress
{

	byte[] getHash();

	void setHash(byte[] hash);

	byte[] getPublicKey();

	void setPublicKey(byte[] publicKey);

	String getName();

	void setName(String name);

}