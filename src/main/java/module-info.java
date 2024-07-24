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