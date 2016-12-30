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
package de.alpharogroup.mystic.crypt.help;

import java.awt.BorderLayout;
import java.awt.Container;
import java.awt.Frame;
import java.awt.HeadlessException;
import java.awt.Panel;
import java.awt.Toolkit;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JLabel;

import de.alpharogroup.actions.DisposeWindowAction;
import de.alpharogroup.mystic.crypt.Messages;

/**
 * The Class InfoJDialog.
 */
public class InfoJDialog extends JDialog {

	/** The Constant PLACEHOLDER_LABEL. */
	private static final String PLACEHOLDER_LABEL = Messages.getString("info.dialg.label.placeholder"); //$NON-NLS-1$ "
																										// ";

	/** The Constant BUTTONLABEL_CLOSE. */
	private static final String BUTTONLABEL_CLOSE = Messages.getString("info.dialg.label.close"); //$NON-NLS-1$ "Close";
	/** The generaded serialVersionUID. */
	private static final long serialVersionUID = 5646178025613269032L;

	/** The panel. */
	private final InfoJPanel panel;

	/** The button close. */
	private final JButton buttonClose;

	/** The label placeholder. */
	private final JLabel labelPlaceholder;

	/**
	 * Instantiates a new info j dialog.
	 *
	 * @param owner
	 *            the owner
	 * @param title
	 *            the title
	 * @throws HeadlessException
	 *             the headless exception
	 */
	public InfoJDialog(final Frame owner, final String title) throws HeadlessException {
		setTitle(title);
		setModal(true);
		buttonClose = new JButton(BUTTONLABEL_CLOSE);
		buttonClose.addActionListener(new DisposeWindowAction(this));
		labelPlaceholder = new JLabel(PLACEHOLDER_LABEL);
		final Panel buttons = new Panel();
		buttons.add(buttonClose, BorderLayout.EAST);
		buttons.add(labelPlaceholder, BorderLayout.CENTER);
		panel = new InfoJPanel();
		final Container container = getContentPane();
		container.add(panel, BorderLayout.CENTER);
		container.add(buttons, BorderLayout.SOUTH);
		final int x = (int) Toolkit.getDefaultToolkit().getScreenSize().getWidth();
		final int y = (int) Toolkit.getDefaultToolkit().getScreenSize().getHeight();
		setLocation((x / 3), (y / 3));
		setSize((x / 3), (y / 3));
	}

}