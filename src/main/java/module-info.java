module io.github.astrapisixtynine.mystic.crypt
{
	requires com.google.common;
	requires file.worker;
	requires io.github.astrapisixtynine.crypt.api;
	requires io.github.astrapisixtynine.crypt.data;
	requires io.github.astrapisixtynine.throwable;
	requires jobj.cloner.main;
	requires jobj.core.main;
	requires org.apache.commons.codec;
	requires org.apache.commons.io;
	requires org.apache.commons.lang3;
	requires org.bouncycastle.provider;
	requires randomizer.main;
	requires silly.bean.main;
	requires silly.collection;


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
	exports io.github.astrapi69.mystic.crypt.sha;
	exports io.github.astrapi69.mystic.crypt.simple;
	exports io.github.astrapi69.mystic.crypt.ssl;

}