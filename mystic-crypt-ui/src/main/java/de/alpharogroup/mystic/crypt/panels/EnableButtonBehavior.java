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