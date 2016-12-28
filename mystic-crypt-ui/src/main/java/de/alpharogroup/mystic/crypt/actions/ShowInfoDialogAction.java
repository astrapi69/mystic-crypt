package de.alpharogroup.mystic.crypt.actions;

import java.awt.event.ActionEvent;

import javax.swing.AbstractAction;

import de.alpharogroup.mystic.crypt.MainFrame;
import de.alpharogroup.mystic.crypt.help.InfoJDialog;

/**
 * The class {@link ShowInfoDialogAction}.
 */
public class ShowInfoDialogAction extends AbstractAction {

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = 1L;
	/** The Constant INFO_TITLE. */
	private static final String INFO_TITLE = "Info";

	/**
	 * Instantiates a new {@link ShowInfoDialogAction}.
	 *
	 * @param name
	 *            the name
	 */
	public ShowInfoDialogAction(final String name) {
		super(name);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void actionPerformed(final ActionEvent e) {
		final InfoJDialog info = new InfoJDialog(MainFrame.getInstance(), INFO_TITLE);
		info.setVisible(true);
	}

}