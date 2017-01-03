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

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;

import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextArea;

import de.alpharogroup.mystic.crypt.Messages;

/**
 * The Class InfoJPanel.
 */
public class InfoJPanel extends JPanel {

	/** The Constant LABEL_COPYRIGHTHOLDER. */
	private static final String LABEL_COPYRIGHTHOLDER = Messages.getString("InfoJPanel.copyright.value"); //$NON-NLS-1$

	/** The Constant LABEL_COPYRIGHT. */
	private static final String LABEL_COPYRIGHT = Messages.getString("InfoJPanel.copyright.key"); //$NON-NLS-1$

	/** The Constant LABEL_VERSION_NUMBER. */
	private static final String LABEL_VERSION_NUMBER = Messages.getString("InfoJPanel.version.value"); //$NON-NLS-1$

	/** The Constant LABEL_VERSION. */
	private static final String LABEL_VERSION = Messages.getString("InfoJPanel.version.key"); //$NON-NLS-1$

	/** The Constant LABEL_APPLICATION_NAME_VALUE. */
	private static final String LABEL_APPLICATION_NAME_VALUE = Messages.getString("InfoJPanel.application.name.value"); //$NON-NLS-1$

	/** The Constant LABEL_APPLICATION_NAME. */
	private static final String LABEL_APPLICATION_NAME = Messages.getString("InfoJPanel.application.name.key"); //$NON-NLS-1$

	/** The Constant WARNING_TEXT. */
	private static final String WARNING_TEXT = Messages.getString("InfoJPanel.warning"); //$NON-NLS-1$

	/** The generaded serialVersionUID. */
	private static final long serialVersionUID = -5173953432663432688L;

	/** The application name. */
	private JLabel applicationName;

	/** The label application name. */
	private JLabel labelApplicationName;

	/** The version number. */
	private JLabel versionNumber;

	/** The labelversion number. */
	private JLabel labelversionNumber;

	/** The copyright. */
	private JLabel copyright;

	/** The label copyright. */
	private JLabel labelCopyright;

	/** The warning. */
	private String warning;

	/** The jta warning. */
	private JTextArea jtaWarning;

	/**
	 * Instantiates a new {@link InfoJPanel}.
	 */
	public InfoJPanel() {
		newLayout();
	}

	/**
	 * Creates the layout.
	 */
	private void newLayout() {
		final Insets oneInsent = new Insets(1, 1, 1, 1);
		final GridBagLayout gbl = new GridBagLayout();
		final GridBagConstraints gbc = new GridBagConstraints();
		setLayout(gbl);
		warning = WARNING_TEXT;
		labelApplicationName = new JLabel(LABEL_APPLICATION_NAME);
		applicationName = new JLabel(LABEL_APPLICATION_NAME_VALUE);
		labelversionNumber = new JLabel(LABEL_VERSION);
		versionNumber = new JLabel(LABEL_VERSION_NUMBER);
		labelCopyright = new JLabel(LABEL_COPYRIGHT);
		copyright = new JLabel(LABEL_COPYRIGHTHOLDER);
		jtaWarning = new JTextArea(warning);
		jtaWarning.setLineWrap(true);
		jtaWarning.setWrapStyleWord(true);
		jtaWarning.setEditable(false);

		gbc.anchor = GridBagConstraints.EAST;
		gbc.fill = GridBagConstraints.NONE;
		gbc.insets = oneInsent;
		gbc.gridx = 0;
		gbc.gridy = 0;
		gbc.gridwidth = 1;
		gbc.gridheight = 1;
		gbc.weighty = 1;
		gbc.weightx = 1;
		gbc.ipadx = 0;
		gbc.ipady = 0;
		gbl.setConstraints(labelApplicationName, gbc);
		add(labelApplicationName);

		gbc.anchor = GridBagConstraints.WEST;
		gbc.fill = GridBagConstraints.NONE;
		gbc.insets = oneInsent;
		gbc.gridx = 1;
		gbc.gridy = 0;
		gbc.gridwidth = 1;
		gbc.gridheight = 1;
		gbc.weighty = 1;
		gbc.weightx = 1;
		gbc.ipadx = 0;
		gbc.ipady = 0;
		gbl.setConstraints(applicationName, gbc);
		add(applicationName);

		gbc.anchor = GridBagConstraints.EAST;
		gbc.fill = GridBagConstraints.NONE;
		gbc.insets = oneInsent;
		gbc.gridx = 0;
		gbc.gridy = 1;
		gbc.gridwidth = 1;
		gbc.gridheight = 1;
		gbc.weighty = 1;
		gbc.weightx = 1;
		gbc.ipadx = 0;
		gbc.ipady = 0;
		gbl.setConstraints(labelversionNumber, gbc);
		add(labelversionNumber);

		gbc.anchor = GridBagConstraints.WEST;
		gbc.fill = GridBagConstraints.NONE;
		gbc.insets = oneInsent;
		gbc.gridx = 1;
		gbc.gridy = 1;
		gbc.gridwidth = 1;
		gbc.gridheight = 1;
		gbc.weighty = 1;
		gbc.weightx = 1;
		gbc.ipadx = 0;
		gbc.ipady = 0;
		gbl.setConstraints(versionNumber, gbc);
		add(versionNumber);

		gbc.anchor = GridBagConstraints.EAST;
		gbc.fill = GridBagConstraints.NONE;
		gbc.insets = oneInsent;
		gbc.gridx = 0;
		gbc.gridy = 2;
		gbc.gridwidth = 1;
		gbc.gridheight = 1;
		gbc.weighty = 1;
		gbc.weightx = 1;
		gbc.ipadx = 0;
		gbc.ipady = 0;
		gbl.setConstraints(labelCopyright, gbc);
		add(labelCopyright);

		gbc.anchor = GridBagConstraints.WEST;
		gbc.fill = GridBagConstraints.NONE;
		gbc.insets = oneInsent;
		gbc.gridx = 1;
		gbc.gridy = 2;
		gbc.gridwidth = 1;
		gbc.gridheight = 1;
		gbc.weighty = 1;
		gbc.weightx = 1;
		gbc.ipadx = 0;
		gbc.ipady = 0;
		gbl.setConstraints(copyright, gbc);
		add(copyright);

	}

}
