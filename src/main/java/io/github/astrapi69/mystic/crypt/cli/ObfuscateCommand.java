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
 * Obfuscates text with a character-substitution map. Each {@code --rule a=x} maps a character to
 * its replacement; the inverse {@link DisentangleCommand} reverses it with the same rules.
 */
@Command(name = "obfuscate", mixinStandardHelpOptions = true, //
	description = "Obfuscate text with a character-substitution map (--rule a=x, repeatable).")
public class ObfuscateCommand implements Callable<Integer>
{

	@Option(names = "--rule", required = true, description = "A character substitution a=x (repeatable).")
	Map<Character, Character> rules;

	@Option(names = "--text", description = "The text to obfuscate. Prefer --text-stdin for larger input.")
	String text;

	@Option(names = "--text-stdin", description = "Read the text from standard input.")
	boolean textStdin;

	@Override
	public Integer call()
	{
		String input = CliSupport.resolveText(text, textStdin);
		System.out
			.println(SimpleObfuscatorExtensions.obfuscateBiMap(HashBiMap.create(rules), input));
		return 0;
	}
}
