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
package de.alpharogroup.crypto;

import lombok.AccessLevel;
import lombok.Builder;
import lombok.Data;
import lombok.experimental.FieldDefaults;

/**
 * The class {@link Router} holds data for a router
 */
@Data
@Builder(toBuilder = true)
@FieldDefaults(level = AccessLevel.PRIVATE)
public class Router
{

	/** The access type. */
	String accessType;

	/** The model. */
	String model;

	/** The notes. */
	String notes;

	/** The permissions. */
	String permissions;

	/** The pw. */
	String pw;

	/** The username. */
	String username;

	/** The vendor. */
	String vendor;

	/** The version. */
	String version;

	/**
	 * To line.
	 *
	 * @return the string
	 */
	public String toLine()
	{
		final StringBuilder sb = new StringBuilder();
		sb.append(this.vendor);
		sb.append(";");
		sb.append(this.model);
		sb.append(";");
		sb.append(this.version);
		sb.append(";");
		sb.append(this.accessType);
		sb.append(";");
		sb.append(this.username);
		sb.append(";");
		sb.append(this.pw);
		sb.append(";");
		sb.append(this.permissions);
		sb.append(";");
		sb.append(this.notes);
		sb.append(";");
		return sb.toString();
	}
}
