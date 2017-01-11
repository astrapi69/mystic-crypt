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

import java.awt.event.ActionEvent;

import javax.swing.GroupLayout;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.LayoutStyle;

/**
 * The class {@link EnDecryptPanel} holds components for encrypt and decrypt text.
 */
public class EnDecryptPanel extends JPanel
{

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = 1L;

	/** The btn decrypt. */
	private JButton btnDecrypt;

	/** The btn encrypt. */
	private JButton btnEncrypt;

	/** The lbl encrypted. */
	private JLabel lblEncrypted;

	/** The lbl to encrypt. */
	private JLabel lblToEncrypt;

	/** The scp encrypted. */
	private JScrollPane scpEncrypted;

	/** The scp to encrypt. */
	private JScrollPane scpToEncrypt;

	/** The txt encrypted. */
	private JTextArea txtEncrypted;

	/** The txt to encrypt. */
	private JTextArea txtToEncrypt;

	/**
	 * Instantiates a new {@link EnDecryptPanel}.
	 */
	public EnDecryptPanel()
	{
		initialize();
	}


	/**
	 * Initialize Panel.
	 */
	protected void initialize()
	{
		initializeComponents();
		initializeLayout();
	}


	/**
	 * Initialize components.
	 */
	protected void initializeComponents()
	{
		lblToEncrypt = new JLabel();
		scpToEncrypt = new JScrollPane();
		txtToEncrypt = new JTextArea();
		btnEncrypt = new JButton();
		btnDecrypt = new JButton();
		scpEncrypted = new JScrollPane();
		txtEncrypted = new JTextArea();
		lblEncrypted = new JLabel();

		lblToEncrypt.setText("Text to encrypt");

		txtToEncrypt.setColumns(20);
		txtToEncrypt.setRows(5);
		scpToEncrypt.setViewportView(txtToEncrypt);

		btnEncrypt.setText("Encrypt >");
		btnEncrypt.addActionListener(actionEvent -> onEncrypt(actionEvent));
		EnableButtonBehavior.builder()
		.buttonModel(btnEncrypt.getModel())
		.document(txtToEncrypt.getDocument())
		.build();

		btnDecrypt.setText("< Decrypt");
		btnDecrypt.addActionListener(actionEvent -> onDecrypt(actionEvent));
		EnableButtonBehavior.builder()
		.buttonModel(btnDecrypt.getModel())
		.document(txtEncrypted.getDocument())
		.build();

		txtEncrypted.setColumns(20);
		txtEncrypted.setRows(5);
		scpEncrypted.setViewportView(txtEncrypted);

		lblEncrypted.setText("Text is encrypted");

	}

	/**
	 * Initialize layout.
	 */
	protected void initializeLayout()
	{
		final GroupLayout layout = new GroupLayout(this);
		this.setLayout(layout);
		layout.setHorizontalGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
			.addGroup(layout.createSequentialGroup().addContainerGap()
				.addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING, false)
					.addComponent(lblToEncrypt, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE,
						Short.MAX_VALUE)
					.addComponent(scpToEncrypt, GroupLayout.DEFAULT_SIZE, 381, Short.MAX_VALUE))
				.addGap(28, 28, 28)
				.addGroup(layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
					.addComponent(btnDecrypt, GroupLayout.PREFERRED_SIZE, 156,
						GroupLayout.PREFERRED_SIZE)
					.addComponent(btnEncrypt, GroupLayout.PREFERRED_SIZE, 156,
						GroupLayout.PREFERRED_SIZE))
				.addGap(28, 28, 28)
				.addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING, false)
					.addComponent(scpEncrypted, GroupLayout.DEFAULT_SIZE, 381, Short.MAX_VALUE)
					.addComponent(lblEncrypted, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE,
						Short.MAX_VALUE))
				.addContainerGap(GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)));
		layout.setVerticalGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
			.addGroup(layout.createSequentialGroup().addContainerGap()
				.addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
					.addComponent(lblToEncrypt, GroupLayout.PREFERRED_SIZE, 31,
						GroupLayout.PREFERRED_SIZE)
					.addComponent(lblEncrypted, GroupLayout.PREFERRED_SIZE, 31,
						GroupLayout.PREFERRED_SIZE))
				.addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
				.addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
					.addGroup(layout.createSequentialGroup().addGap(19, 19, 19)
						.addComponent(btnEncrypt).addGap(53, 53, 53).addComponent(btnDecrypt))
					.addComponent(scpEncrypted, GroupLayout.PREFERRED_SIZE, 148,
						GroupLayout.PREFERRED_SIZE)
					.addComponent(scpToEncrypt, GroupLayout.PREFERRED_SIZE, 148,
						GroupLayout.PREFERRED_SIZE))
				.addContainerGap(39, Short.MAX_VALUE)));
	}

	/**
	 * Callback method that can be overwritten to provide specific action for the on decrypt.
	 *
	 * @param actionEvent the action event
	 */
	protected void onDecrypt(final ActionEvent actionEvent)
	{
		System.out.println("onDecrypt");
	}


	/**
	 * Callback method that can be overwritten to provide specific action for the on encrypt.
	 *
	 * @param actionEvent the action event
	 */
	protected void onEncrypt(final ActionEvent actionEvent)
	{
		System.out.println("onEncrypt");

	}

}