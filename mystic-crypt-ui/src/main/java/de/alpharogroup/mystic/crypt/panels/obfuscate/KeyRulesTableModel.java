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
package de.alpharogroup.mystic.crypt.panels.obfuscate;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import de.alpharogroup.collections.pairs.KeyValuePair;
import de.alpharogroup.swing.tablemodel.GenericTableModel;
import lombok.Builder;
import lombok.Getter;
import lombok.ToString;

/**
 * The class {@link KeyRulesTableModel}.
 */
@Getter
@ToString
@Builder
public class KeyRulesTableModel extends GenericTableModel<KeyValuePair<String, String>>
{

	/**
	 * The constant serialVersionUID.
	 */
	private static final long serialVersionUID = 1L;

	/** The Constant ORIGINAL_CHAR. */
	public static final String ORIGINAL_CHAR = "Original character";

	/** The Constant REPLACE_WITH. */
	public static final String REPLACE_WITH = "Replace with";

	/** The column names. */
	private final String[] columnNames = { ORIGINAL_CHAR, REPLACE_WITH };

	/** The can edit. */
	private final boolean[] canEdit = new boolean[] { false, false };

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Class<?> getColumnClass(final int c)
	{
		switch (c)
		{
			case 0 :
				return String.class;
			case 1 :
				return String.class;
			default :
				return String.class;
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public int getColumnCount()
	{
		return columnNames.length;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String getColumnName(final int col)
	{
		return columnNames[col];
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Object getValueAt(final int row, final int col)
	{
		final KeyValuePair<String, String> permission = getData().get(row);
		switch (col)
		{
			case 0 :
				return permission.getKey();
			case 1 :
				return permission.getValue();
			default :
				return null;
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean isCellEditable(final int rowIndex, final int columnIndex)
	{
		return canEdit[columnIndex];
	}

	/**
	 * To map.
	 *
	 * @return the map
	 */
	public Map<String, String> toMap() {
		final List<KeyValuePair<String, String>> data = getData();
		final Map<String, String> map = new HashMap<>();
		for(final KeyValuePair<String, String> row : data) {
			map.put(row.getKey(), row.getValue());
		}
		return map;

	}

}