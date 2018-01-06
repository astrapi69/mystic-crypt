package de.alpharogroup.crypto.obfuscation.rule;

import java.util.Comparator;

public class ObfuscationOperationRuleComparator implements Comparator<ObfuscationOperationRule<Character, String>>
{

	@Override
	public int compare(ObfuscationOperationRule<Character, String> o1,
		ObfuscationOperationRule<Character, String> o2)
	{
		int length1 = o1.getReplaceWith().length();
		int length2 = o2.getReplaceWith().length();
		if(length1 == length2) {
			return o1.getReplaceWith().compareTo(o2.getReplaceWith());
		}
		return length2 - length1;
	}

}
