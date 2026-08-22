/**
 * The MIT License
 *
 * Copyright (C) 2015 Asterios Raptis
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
 * associated documentation files (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge, publish, distribute,
 * sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or
 * substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
 * NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
/**
 * The MIT License
 */
module io.github.astrapisixtynine.mystic.crypt
{
	// The following five modules contribute types to the public API of this module (return types,
	// parameter types, type arguments and supertypes of exported classes), so they have to be
	// readable by every consumer of this module as well - hence "requires transitive":
	// com.google.common ........ BiMap in ObfuscatorExtensions / CharacterObfuscator
	// io.github.astrapi69.crypt.api .......... StringEncryptor and the other Cryptor interfaces
	// io.github.astrapisixtynine.crypt.data .. CryptModel, ObfuscationOperationRule
	// io.github.astrapisixtynine.silly.bean .. KeyValuePair in ObfuscatorExtensions
	// org.bouncycastle.provider .............. JPAKEParticipant in JpakeKeyExchange
	requires transitive com.google.common;
	requires io.github.astrapisixtynine.file.worker;
	requires transitive io.github.astrapi69.crypt.api;
	requires transitive io.github.astrapisixtynine.crypt.data;
	requires io.github.astrapisixtynine.throwable;
	requires jobj.cloner.main;
	requires io.github.astrapisixtynine.jobj.core;
	requires org.apache.commons.codec;
	requires org.apache.commons.io;
	requires org.apache.commons.lang3;
	requires transitive org.bouncycastle.provider;
	requires randomizer.main;
	requires transitive io.github.astrapisixtynine.silly.bean;
	requires io.github.astrapisixtynine.silly.collection;
	requires org.bouncycastle.pkix;
	// command-line interface
	requires info.picocli;


	exports io.github.astrapi69.mystic.crypt.aead;
	exports io.github.astrapi69.mystic.crypt.algorithm;
	exports io.github.astrapi69.mystic.crypt.base;
	exports io.github.astrapi69.mystic.crypt.chainable;
	exports io.github.astrapi69.mystic.crypt.core;
	exports io.github.astrapi69.mystic.crypt.decorator;
	exports io.github.astrapi69.mystic.crypt.file;
	exports io.github.astrapi69.mystic.crypt.gm;
	exports io.github.astrapi69.mystic.crypt.hex;
	exports io.github.astrapi69.mystic.crypt.io;
	exports io.github.astrapi69.mystic.crypt.key;
	exports io.github.astrapi69.mystic.crypt.obfuscation.character;
	exports io.github.astrapi69.mystic.crypt.obfuscation.simple;
	exports io.github.astrapi69.mystic.crypt.processor.bruteforce;
	exports io.github.astrapi69.mystic.crypt.processor.wordlist;
	exports io.github.astrapi69.mystic.crypt.pw;
	exports io.github.astrapi69.mystic.crypt.secret;
	exports io.github.astrapi69.mystic.crypt.sha;
	exports io.github.astrapi69.mystic.crypt.simple;
	exports io.github.astrapi69.mystic.crypt.srp;
	exports io.github.astrapi69.mystic.crypt.ssl;
	exports io.github.astrapi69.mystic.crypt.cli;

	// picocli reflectively reads the @Command/@Option annotated fields of the CLI classes
	opens io.github.astrapi69.mystic.crypt.cli to info.picocli;

}