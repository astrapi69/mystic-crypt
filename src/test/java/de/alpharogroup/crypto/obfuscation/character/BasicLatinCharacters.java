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
package de.alpharogroup.crypto.obfuscation.character;

public class BasicLatinCharacters
{
	public static final Character[] ASCIIDigitsCharacters = { Character.valueOf((char)0x30), // 0
			Character.valueOf((char)0x31), // 1
			Character.valueOf((char)0x32), // 2
			Character.valueOf((char)0x33), // 3
			Character.valueOf((char)0x34), // 4
			Character.valueOf((char)0x35), // 5
			Character.valueOf((char)0x36), // 6
			Character.valueOf((char)0x37), // 7
			Character.valueOf((char)0x38), // 8
			Character.valueOf((char)0x39), // 9
	};

	public static final Character[] ASCIILowercaseLatinAlphabetCharacters = {
			Character.valueOf((char)0x61), // a
			Character.valueOf((char)0x62), // b
			Character.valueOf((char)0x63), // c
			Character.valueOf((char)0x64), // d
			Character.valueOf((char)0x65), // e
			Character.valueOf((char)0x66), // f
			Character.valueOf((char)0x67), // g
			Character.valueOf((char)0x68), // h
			Character.valueOf((char)0x69), // i
			Character.valueOf((char)0x6a), // j
			Character.valueOf((char)0x6b), // k
			Character.valueOf((char)0x6c), // l
			Character.valueOf((char)0x6d), // m
			Character.valueOf((char)0x6e), // n
			Character.valueOf((char)0x6f), // o
			Character.valueOf((char)0x70), // p
			Character.valueOf((char)0x71), // q
			Character.valueOf((char)0x72), // r
			Character.valueOf((char)0x73), // s
			Character.valueOf((char)0x74), // t
			Character.valueOf((char)0x75), // u
			Character.valueOf((char)0x76), // v
			Character.valueOf((char)0x77), // w
			Character.valueOf((char)0x78), // x
			Character.valueOf((char)0x79), // y
			Character.valueOf((char)0x7a), // z
	};

	public static final Character[] ASCIIPunctuationAndSymbols1Characters = {
			Character.valueOf((char)0x20), // 0x20
			Character.valueOf((char)0x21), // !
			Character.valueOf((char)0x22), // "
			Character.valueOf((char)0x23), // #
			Character.valueOf((char)0x24), // $
			Character.valueOf((char)0x25), // %
			Character.valueOf((char)0x26), // &
			Character.valueOf((char)0x27), // '
			Character.valueOf((char)0x28), // (
			Character.valueOf((char)0x29), // )
			Character.valueOf((char)0x2a), // *
			Character.valueOf((char)0x2b), // +
			Character.valueOf((char)0x2c), // ,
			Character.valueOf((char)0x2d), // -
			Character.valueOf((char)0x2e), // .
			Character.valueOf((char)0x2f), // /
	};

	public static final Character[] ASCIIPunctuationAndSymbols2Characters = {
			Character.valueOf((char)0x3a), // :
			Character.valueOf((char)0x3b), // ;
			Character.valueOf((char)0x3c), // <
			Character.valueOf((char)0x3d), // =
			Character.valueOf((char)0x3e), // >
			Character.valueOf((char)0x3f), // ?
			Character.valueOf((char)0x40) // @
	};

	public static final Character[] ASCIIPunctuationAndSymbols3Characters = {
			Character.valueOf((char)0x5b), // [
			Character.valueOf((char)0x5c), // \
			Character.valueOf((char)0x5d), // ]
			Character.valueOf((char)0x5e), // ^
			Character.valueOf((char)0x5f), // _
			Character.valueOf((char)0x60) // `
	};

	public static final Character[] ASCIIPunctuationAndSymbols4Characters = {
			Character.valueOf((char)0x7b), // {
			Character.valueOf((char)0x7c), // |
			Character.valueOf((char)0x7d), // }
			Character.valueOf((char)0x7e), // ~
	};

	public static final Character[] ASCIIUppercaseLatinAlphabetCharacters = {
			Character.valueOf((char)0x41), // A
			Character.valueOf((char)0x42), // B
			Character.valueOf((char)0x43), // C
			Character.valueOf((char)0x44), // D
			Character.valueOf((char)0x45), // E
			Character.valueOf((char)0x46), // F
			Character.valueOf((char)0x47), // G
			Character.valueOf((char)0x48), // H
			Character.valueOf((char)0x49), // I
			Character.valueOf((char)0x4a), // J
			Character.valueOf((char)0x4b), // K
			Character.valueOf((char)0x4c), // L
			Character.valueOf((char)0x4d), // M
			Character.valueOf((char)0x4e), // N
			Character.valueOf((char)0x4f), // O
			Character.valueOf((char)0x50), // P
			Character.valueOf((char)0x51), // Q
			Character.valueOf((char)0x52), // R
			Character.valueOf((char)0x53), // S
			Character.valueOf((char)0x54), // T
			Character.valueOf((char)0x55), // U
			Character.valueOf((char)0x56), // V
			Character.valueOf((char)0x57), // W
			Character.valueOf((char)0x58), // X
			Character.valueOf((char)0x59), // Y
			Character.valueOf((char)0x5a), // Z
	};

	public static final Character[] C0Control1Characters = { Character.valueOf((char)0x00),
			Character.valueOf((char)0x01), Character.valueOf((char)0x02),
			Character.valueOf((char)0x03), Character.valueOf((char)0x04),
			Character.valueOf((char)0x05), Character.valueOf((char)0x06),
			Character.valueOf((char)0x07), Character.valueOf((char)0x08),
			Character.valueOf((char)0x09), Character.valueOf((char)0x0a),
			Character.valueOf((char)0x0b), Character.valueOf((char)0x0c),
			Character.valueOf((char)0x0d), Character.valueOf((char)0x0e),
			Character.valueOf((char)0x0f), Character.valueOf((char)0x10),
			Character.valueOf((char)0x11), Character.valueOf((char)0x12),
			Character.valueOf((char)0x13), Character.valueOf((char)0x14),
			Character.valueOf((char)0x15), Character.valueOf((char)0x16),
			Character.valueOf((char)0x17), Character.valueOf((char)0x18),
			Character.valueOf((char)0x19), Character.valueOf((char)0x1a),
			Character.valueOf((char)0x1b), Character.valueOf((char)0x1c),
			Character.valueOf((char)0x1d), Character.valueOf((char)0x1e),
			Character.valueOf((char)0x1f), };

	public static final Character[] C0Control2Characters = { Character.valueOf((char)0x7f), // Delete
																							// control
	};

}
