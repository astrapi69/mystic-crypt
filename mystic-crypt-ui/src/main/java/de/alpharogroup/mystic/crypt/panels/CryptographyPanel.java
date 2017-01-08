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

import javax.swing.DefaultComboBoxModel;
import javax.swing.GroupLayout;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.LayoutStyle;

import de.alpharogroup.crypto.key.KeySize;

/**
 * The class {@link CryptographyPanel} can generate private and public keys and save them to files.
 */
public class CryptographyPanel extends JPanel
{

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = 1L;

	/** The btn clear. */
	private JButton btnClear;

	/** The btn generate. */
	private JButton btnGenerate;

	/** The btn save private key. */
	private JButton btnSavePrivateKey;

	/** The btn save public key. */
	private JButton btnSavePublicKey;

	/** The cmb key size. */
	private JComboBox<String> cmbKeySize;

	/** The lbl key size. */
	private JLabel lblKeySize;

	/** The lbl private key. */
	private JLabel lblPrivateKey;

	/** The lbl public key. */
	private JLabel lblPublicKey;

	/** The scp private key. */
	private JScrollPane scpPrivateKey;

	/** The scp public key. */
	private JScrollPane scpPublicKey;

	/** The txt private key. */
	private JTextArea txtPrivateKey;

	/** The txt public key. */
	private JTextArea txtPublicKey;

	/**
	 * Instantiates a new {@link CryptographyPanel}.
	 */
	public CryptographyPanel()
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
	@SuppressWarnings({ "unchecked", "rawtypes" })
	protected void initializeComponents()
	{

		scpPrivateKey = new JScrollPane();
		txtPrivateKey = new JTextArea();
		cmbKeySize = new JComboBox<>();
		lblPrivateKey = new JLabel();
		lblKeySize = new JLabel();
		scpPublicKey = new JScrollPane();
		txtPublicKey = new JTextArea();
		lblPublicKey = new JLabel();
		btnGenerate = new JButton();
		btnClear = new JButton();
		btnSavePrivateKey = new JButton();
		btnSavePublicKey = new JButton();

		cmbKeySize.addActionListener(actionEvent -> onChangeKeySize(actionEvent));
		btnGenerate.addActionListener(actionEvent -> onGenerate(actionEvent));
		btnClear.addActionListener(actionEvent -> onClear(actionEvent));
		btnSavePrivateKey.addActionListener(actionEvent -> onSavePrivateKey(actionEvent));
		btnSavePublicKey.addActionListener(actionEvent -> onSavePublicKey(actionEvent));

		txtPrivateKey.setColumns(20);
		txtPrivateKey.setRows(5);
		scpPrivateKey.setViewportView(txtPrivateKey);
		txtPrivateKey.getAccessibleContext().setAccessibleDescription("");

		cmbKeySize.setModel(new DefaultComboBoxModel(KeySize.values()));
		cmbKeySize.setSelectedItem(KeySize.KEYSIZE_1024);

		btnGenerate.setText("Generate keys");

		lblPrivateKey.setText("Private key");

		lblKeySize.setText("Keysize");

		txtPublicKey.setColumns(20);
		txtPublicKey.setRows(5);
		scpPublicKey.setViewportView(txtPublicKey);

		lblPublicKey.setText("Public key");

		btnClear.setText("Clear keys");

		btnSavePrivateKey.setText("Save public key");

		btnSavePublicKey.setText("Save public key");

	}

	/**
	 * Initialize layout.
	 */
	protected void initializeLayout()
	{

		final GroupLayout layout = new GroupLayout(this);
		this.setLayout(layout);
		layout
			.setHorizontalGroup(
				layout.createParallelGroup(GroupLayout.Alignment.LEADING).addGroup(layout
					.createSequentialGroup().addGroup(
						layout.createParallelGroup(GroupLayout.Alignment.TRAILING).addGroup(layout
							.createSequentialGroup().addGap(0, 0, Short.MAX_VALUE)
							.addComponent(
								btnSavePrivateKey, GroupLayout.PREFERRED_SIZE, 183,
								GroupLayout.PREFERRED_SIZE))
							.addGroup(layout.createSequentialGroup().addGroup(layout
								.createParallelGroup(GroupLayout.Alignment.LEADING, false)
								.addGroup(layout.createSequentialGroup().addContainerGap()
									.addGroup(layout
										.createParallelGroup(GroupLayout.Alignment.LEADING, false)
										.addComponent(cmbKeySize, 0, GroupLayout.DEFAULT_SIZE,
											Short.MAX_VALUE)
										.addComponent(btnGenerate, GroupLayout.DEFAULT_SIZE, 206,
											Short.MAX_VALUE)))
								.addGroup(layout.createSequentialGroup().addGap(21, 21, 21)
									.addComponent(lblKeySize, GroupLayout.PREFERRED_SIZE, 147,
										GroupLayout.PREFERRED_SIZE))
								.addGroup(layout.createSequentialGroup().addContainerGap()
									.addComponent(btnClear, GroupLayout.DEFAULT_SIZE,
										GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)))
								.addPreferredGap(LayoutStyle.ComponentPlacement.RELATED,
									GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
								.addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
									.addComponent(scpPrivateKey, GroupLayout.PREFERRED_SIZE, 344,
										GroupLayout.PREFERRED_SIZE)
									.addComponent(lblPrivateKey, GroupLayout.PREFERRED_SIZE, 147,
										GroupLayout.PREFERRED_SIZE))))
					.addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
						.addGroup(layout.createSequentialGroup().addGap(48, 48, 48)
							.addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
								.addComponent(lblPublicKey, GroupLayout.PREFERRED_SIZE, 147,
									GroupLayout.PREFERRED_SIZE)
								.addComponent(scpPublicKey, GroupLayout.PREFERRED_SIZE, 344,
									GroupLayout.PREFERRED_SIZE))
							.addContainerGap(GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
						.addGroup(GroupLayout.Alignment.TRAILING,
							layout.createSequentialGroup()
								.addPreferredGap(LayoutStyle.ComponentPlacement.RELATED,
									GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
								.addComponent(btnSavePublicKey, GroupLayout.PREFERRED_SIZE, 146,
									GroupLayout.PREFERRED_SIZE)
								.addGap(25, 25, 25)))));
		layout.setVerticalGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
			.addGroup(layout.createSequentialGroup().addGap(26, 26, 26)
				.addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
					.addComponent(lblPrivateKey, GroupLayout.PREFERRED_SIZE, 29,
						GroupLayout.PREFERRED_SIZE)
					.addComponent(lblKeySize, GroupLayout.PREFERRED_SIZE, 29,
						GroupLayout.PREFERRED_SIZE)
					.addComponent(lblPublicKey, GroupLayout.PREFERRED_SIZE, 29,
						GroupLayout.PREFERRED_SIZE))
				.addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
				.addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING, false)
					.addComponent(scpPublicKey, GroupLayout.DEFAULT_SIZE, 265, Short.MAX_VALUE)
					.addGroup(layout.createSequentialGroup()
						.addComponent(cmbKeySize, GroupLayout.PREFERRED_SIZE, 43,
							GroupLayout.PREFERRED_SIZE)
						.addGap(18, 18, 18)
						.addComponent(btnGenerate, GroupLayout.PREFERRED_SIZE, 41,
							GroupLayout.PREFERRED_SIZE)
						.addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED).addComponent(
							btnClear, GroupLayout.PREFERRED_SIZE, 41, GroupLayout.PREFERRED_SIZE))
					.addComponent(scpPrivateKey))
				.addGap(18, 18, 18)
				.addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
					.addComponent(btnSavePrivateKey, GroupLayout.PREFERRED_SIZE, 41,
						GroupLayout.PREFERRED_SIZE)
					.addComponent(btnSavePublicKey, GroupLayout.PREFERRED_SIZE, 41,
						GroupLayout.PREFERRED_SIZE))
				.addContainerGap(22, Short.MAX_VALUE)));
	}

	/**
	 * Callback method that can be overwritten to provide specific action for the on change key
	 * size.
	 *
	 * @param actionEvent
	 *            the action event
	 */
	protected void onChangeKeySize(final ActionEvent actionEvent)
	{
		final Object selected = cmbKeySize.getSelectedItem();
		System.out.println("selected item:" + selected);
	}

	/**
	 * Callback method that can be overwritten to provide specific action for the on save public
	 * key.
	 *
	 * @param actionEvent
	 *            the action event
	 */
	protected void onSavePublicKey(final ActionEvent actionEvent)
	{
		System.out.println("onSavePublicKey");
	}

	/**
	 * Callback method that can be overwritten to provide specific action for the on save private
	 * key.
	 *
	 * @param actionEvent
	 *            the action event
	 */
	protected void onSavePrivateKey(final ActionEvent actionEvent)
	{
		System.out.println("onSavePrivateKey");
	}

	/**
	 * Callback method that can be overwritten to provide specific action for the on clear.
	 *
	 * @param actionEvent
	 *            the action event
	 */
	protected void onClear(final ActionEvent actionEvent)
	{
		System.out.println("onClear");
	}

	/**
	 * Callback method that can be overwritten to provide specific action for the on generate.
	 *
	 * @param actionEvent
	 *            the action event
	 */
	protected void onGenerate(final ActionEvent actionEvent)
	{
		System.out.println("onGenerate");
	}

}
