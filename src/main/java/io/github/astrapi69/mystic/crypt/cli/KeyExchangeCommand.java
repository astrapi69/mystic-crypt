/*
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
package io.github.astrapi69.mystic.crypt.cli;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.concurrent.Callable;

import javax.crypto.SecretKey;

import io.github.astrapi69.mystic.crypt.key.KeyExchangeSupport;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

/**
 * A key exchange between two people, as three separate runs.
 * <p>
 * Where {@code kem} plays both sides against itself and shows the mathematics, this is the exchange
 * as it is used: each side holds only its own half, and what travels between them is a public key
 * and a handshake.
 */
@Command(name = "keyx", mixinStandardHelpOptions = true, //
	description = "Exchange a shared secret with another person: 'new' on the recipient's side, "
		+ "'send' on the sender's, 'receive' back on the recipient's.", //
	subcommands = { KeyExchangeCommand.NewCommand.class, KeyExchangeCommand.SendCommand.class,
			KeyExchangeCommand.ReceiveCommand.class })
public class KeyExchangeCommand implements Runnable
{

	/**
	 * Instantiates a new {@link KeyExchangeCommand}.
	 * <p>
	 * Declared explicitly, and public, because picocli builds this subcommand reflectively through
	 * its default factory when {@link MysticCryptCli} dispatches to it; the class must therefore
	 * keep an accessible no-argument constructor.
	 */
	public KeyExchangeCommand()
	{
	}

	@Override
	public void run()
	{
		CommandLine.usage(this, System.out);
	}

	/** Writes the given text to a file, or prints it when no file was given. */
	private static void emit(final File target, final String label, final String text)
		throws IOException
	{
		if (target != null)
		{
			Files.writeString(target.toPath(), text + System.lineSeparator(),
				StandardCharsets.UTF_8);
			System.out.println(label + " written to " + target.getPath());
		}
		else
		{
			System.out.println(label + ": " + text);
		}
	}

	/** Reads one envelope from a file, trimmed of the trailing newline a file carries. */
	private static String readEnvelope(final File source) throws IOException
	{
		return Files.readString(source.toPath(), StandardCharsets.UTF_8).trim();
	}

	/**
	 * Sets up the recipient's side of an exchange.
	 */
	@Command(name = "new", mixinStandardHelpOptions = true, //
		description = "Generate this side's key pair. Exit code 0 = generated, 2 = error.")
	public static class NewCommand implements Callable<Integer>
	{

		/**
		 * Instantiates a new {@link NewCommand}.
		 * <p>
		 * Declared explicitly, and public, because picocli builds this subcommand reflectively
		 * through its default factory; the class must keep an accessible no-argument constructor.
		 */
		public NewCommand()
		{
		}

		@Option(names = { "-a", "--algorithm" }, defaultValue = KeyExchangeSupport.ML_KEM_768, //
			description = "The exchange algorithm (default: ${DEFAULT-VALUE}).")
		String algorithm;

		@Option(names = { "-k",
				"--key" }, required = true, description = "The file to write this side's private key to.")
		File key;

		@Option(names = { "-p",
				"--public" }, description = "The file to write the public half to. Without it the public half is printed.")
		File publicKey;

		@Override
		public Integer call()
		{
			try
			{
				KeyExchangeSupport.Party party = KeyExchangeSupport.newParty(algorithm);
				Files.writeString(key.toPath(),
					KeyExchangeSupport.privateKeyOf(party) + System.lineSeparator(),
					StandardCharsets.UTF_8);
				System.out.println("algorithm: " + algorithm);
				System.out.println("private key written to " + key.getPath()
					+ " - this file is the secret half, hand out only the public one");
				emit(publicKey, "public key", KeyExchangeSupport.publicKeyOf(party));
				return 0;
			}
			catch (Exception exception)
			{
				System.err.println(CliSupport.error(exception.getMessage()));
				return 2;
			}
		}
	}

	/**
	 * The sender's side: encapsulates against the recipient's public half.
	 */
	@Command(name = "send", mixinStandardHelpOptions = true, //
		description = "Take the recipient's public key and produce a handshake and a shared "
			+ "secret. Exit code 0 = done, 2 = error.")
	public static class SendCommand implements Callable<Integer>
	{

		/**
		 * Instantiates a new {@link SendCommand}.
		 * <p>
		 * Declared explicitly, and public, because picocli builds this subcommand reflectively
		 * through its default factory; the class must keep an accessible no-argument constructor.
		 */
		public SendCommand()
		{
		}

		@Option(names = { "-r",
				"--recipient" }, required = true, description = "The file holding the recipient's public key.")
		File recipient;

		@Option(names = { "-m",
				"--message" }, description = "A message to encrypt with the derived secret.")
		String message;

		@Option(names = { "-o",
				"--out" }, description = "The file to write the handshake to. Without it the handshake is printed.")
		File out;

		@Option(names = { "-e",
				"--encrypted" }, description = "The file to write the encrypted message to.")
		File encrypted;

		@Override
		public Integer call()
		{
			try
			{
				String publicKey = readEnvelope(recipient);
				KeyExchangeSupport.Handshake handshake = KeyExchangeSupport.encapsulate(publicKey);
				System.out.println("algorithm: " + KeyExchangeSupport.algorithmOf(publicKey));
				emit(out, "handshake", handshake.handshake());
				System.out.println("shared secret fingerprint: "
					+ KeyExchangeSupport.fingerprintOf(handshake.sharedSecret())
					+ " - read it out to the other side to check that both match");
				if (message != null)
				{
					emit(encrypted, "encrypted message", KeyExchangeSupport.encryptMessage(
						handshake.sharedSecret(), message.getBytes(StandardCharsets.UTF_8)));
				}
				return 0;
			}
			catch (Exception exception)
			{
				System.err.println(CliSupport.error(exception.getMessage()));
				return 2;
			}
		}
	}

	/**
	 * The recipient's side again: turns the handshake into the same secret.
	 */
	@Command(name = "receive", mixinStandardHelpOptions = true, //
		description = "Take the handshake and arrive at the same shared secret. "
			+ "Exit code 0 = done, 2 = error.")
	public static class ReceiveCommand implements Callable<Integer>
	{

		/**
		 * Instantiates a new {@link ReceiveCommand}.
		 * <p>
		 * Declared explicitly, and public, because picocli builds this subcommand reflectively
		 * through its default factory; the class must keep an accessible no-argument constructor.
		 */
		public ReceiveCommand()
		{
		}

		@Option(names = { "-k",
				"--key" }, required = true, description = "The file holding this side's private key.")
		File key;

		@Option(names = { "-s",
				"--handshake" }, required = true, description = "The file holding the handshake that came back.")
		File handshake;

		@Option(names = { "-e",
				"--encrypted" }, description = "The file holding the encrypted message to read.")
		File encrypted;

		@Override
		public Integer call()
		{
			try
			{
				KeyExchangeSupport.Party party = KeyExchangeSupport.partyFrom(readEnvelope(key));
				SecretKey sharedSecret = KeyExchangeSupport.decapsulate(party,
					readEnvelope(handshake));
				System.out.println("algorithm: " + party.algorithm());
				System.out.println(
					"shared secret fingerprint: " + KeyExchangeSupport.fingerprintOf(sharedSecret)
						+ " - it must match the one the other side read out");
				if (encrypted != null)
				{
					byte[] plain = KeyExchangeSupport.decryptMessage(sharedSecret,
						readEnvelope(encrypted));
					System.out.println("message: " + new String(plain, StandardCharsets.UTF_8));
				}
				return 0;
			}
			catch (Exception exception)
			{
				System.err.println(CliSupport.error(exception.getMessage()));
				return 2;
			}
		}
	}
}
