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
package io.github.astrapi69.mystic.crypt.cli;

import java.util.Map;
import java.util.concurrent.Callable;

import com.google.common.collect.HashBiMap;

import io.github.astrapi69.mystic.crypt.obfuscation.simple.SimpleObfuscatorExtensions;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

/**
 * Reverses {@link ObfuscateCommand}: given the same character-substitution rules, it recovers the
 * original text from obfuscated text.
 */
@Command(name = "disentangle", mixinStandardHelpOptions = true, //
	description = "Recover text obfuscated by 'obfuscate', using the same --rule a=x map.")
public class DisentangleCommand implements Callable<Integer>
{

	@Option(names = "--rule", required = true, description = "A character substitution a=x (repeatable).")
	Map<Character, Character> rules;

	@Option(names = "--text", description = "The obfuscated text. Prefer --text-stdin for larger input.")
	String text;

	@Option(names = "--text-stdin", description = "Read the obfuscated text from standard input.")
	boolean textStdin;

	@Override
	public Integer call()
	{
		String input = CliSupport.resolveText(text, textStdin);
		System.out
			.println(SimpleObfuscatorExtensions.disentangleBiMap(HashBiMap.create(rules), input));
		return 0;
	}
}
