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
package de.alpharogroup.mystic.crypt.panels;

import javax.swing.ButtonModel;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.Document;

import lombok.Builder;

/**
 * The class {@link EnableButtonBehavior} can be added to a button and a document.
 */
@Builder
public class EnableButtonBehavior implements DocumentListener
{

	/** The button model. */
	private final ButtonModel buttonModel;

	/** The document. */
	private final Document document;

	/** The enabled. */
	private boolean enabled;

	/**
	 * Instantiates a new {@link EnableButtonBehavior}.
	 *
	 * @param buttonModel the button model
	 * @param document the document
	 */
	public EnableButtonBehavior(final ButtonModel buttonModel, final Document document, final boolean enabled)
	{
		this.buttonModel = buttonModel;
		this.document = document;
		this.enabled = enabled;
		this.document.addDocumentListener(this);
		onChange();
	}

	/**
	 * Callback method that can be overwritten to provide specific action on change of document.
	 */
	protected void onChange()
	{
		enabled = false;
		if (this.document.getLength() > 0)
		{
			enabled = true;
		}
		buttonModel.setEnabled(enabled);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void insertUpdate(final DocumentEvent e)
	{
		onChange();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void removeUpdate(final DocumentEvent e)
	{
		onChange();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void changedUpdate(final DocumentEvent e)
	{
		onChange();
	}
}