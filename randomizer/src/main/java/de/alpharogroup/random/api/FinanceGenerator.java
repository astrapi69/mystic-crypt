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
package de.alpharogroup.random.api;

/**
 * The interface {@link FinanceGenerator} provides factory methods for create finance data.
 */
public interface FinanceGenerator
{

	/**
	 * New bic.
	 *
	 * @return the string
	 */
	String newBic();

	/**
	 * New bitcoin address.
	 *
	 * @return the string
	 */
	String newBitcoinAddress();

	/**
	 * New credit card number.
	 *
	 * @return the string
	 */
	String newCreditCardNumber();

	/**
	 * New credit card type.
	 *
	 * @return the string
	 */
	String newCreditCardType();

	/**
	 * New currency code.
	 *
	 * @return the string
	 */
	String newCurrencyCode();

	/**
	 * New currency name.
	 *
	 * @return the string
	 */
	String newCurrencyName();

	/**
	 * New iban.
	 *
	 * @return the string
	 */
	String newIban();
}