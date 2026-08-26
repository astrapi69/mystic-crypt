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

import java.util.Map;
import java.util.concurrent.Callable;

import io.github.astrapi69.mystic.crypt.obfuscation.character.ObfuscatorExtensions;
import io.github.astrapi69.mystic.crypt.obfuscation.simple.SimpleObfuscatorExtensions;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

/**
 * Obfuscates text with a character-substitution map. Each {@code --rule a=x} maps a character to
 * its replacement, and {@code --rule a=x:UPPERCASE@0,3} adds an operation that applies at the named
 * positions instead of the plain replacement. The inverse {@link DisentangleCommand} reverses it
 * with the same rules.
 */
@Command(name = "obfuscate", mixinStandardHelpOptions = true, //
	description = "Obfuscate text with a character-substitution map (--rule a=x), optionally "
		+ "with an operation at named positions (--rule a=x:UPPERCASE@0,3). "
		+ "Exit code 0 = obfuscated, 2 = error.")
public class ObfuscateCommand implements Callable<Integer>
{

	/**
	 * Instantiates a new {@link ObfuscateCommand}.
	 * <p>
	 * Declared explicitly, and public, because picocli builds this subcommand reflectively through
	 * its default factory when {@link MysticCryptCli} dispatches to it; the class must therefore
	 * keep an accessible no-argument constructor.
	 */
	public ObfuscateCommand()
	{
	}

	@Option(names = "--rule", required = true, description = "A character substitution a=x, or an "
		+ "operated one a=x:UPPERCASE@0,3 which writes the operated character at those positions "
		+ "and the substitution everywhere else (repeatable).")
	Map<Character, String> rules;

	@Option(names = "--text", description = "The text to obfuscate. Prefer --text-stdin for larger input.")
	String text;

	@Option(names = "--text-stdin", description = "Read the text from standard input.")
	boolean textStdin;

	@Override
	public Integer call()
	{
		try
		{
			String input = CliSupport.resolveText(text, textStdin);
			ObfuscationRuleSupport.Rules parsed = ObfuscationRuleSupport.parse(rules);
			System.out.println(parsed.isOperated()
				? ObfuscatorExtensions.obfuscateWith(parsed.operated(), input)
				: SimpleObfuscatorExtensions.obfuscateBiMap(parsed.simple(), input));
			return 0;
		}
		catch (Exception exception)
		{
			System.err.println(CliSupport.error(exception.getMessage()));
			return 2;
		}
	}
}
