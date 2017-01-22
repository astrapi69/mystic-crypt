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

import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.ActionEvent;

import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;

import org.apache.log4j.Logger;

import de.alpharogroup.crypto.key.KeySize;
import de.alpharogroup.layout.GridBagLayoutModel;
import de.alpharogroup.layout.InsetsModel;
import de.alpharogroup.layout.LayoutExtensions;
import lombok.Getter;

/**
 * The class {@link CryptographyPanel} can generate private and public keys and save them to files.
 */
@Getter
public class CryptographyPanel extends JPanel
{

	/** The Constant logger. */
	protected static final Logger logger = Logger.getLogger(CryptographyPanel.class.getName());

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

		txtPrivateKey.setEditable(false);
		txtPublicKey.setEditable(false);

		txtPrivateKey.setFont(new Font("monospaced", Font.PLAIN, 12));
		txtPublicKey.setFont(new Font("monospaced", Font.PLAIN, 12));

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

		btnSavePrivateKey.setText("Save private key");

		btnSavePublicKey.setText("Save public key");

	}

	/**
	 * Initialize layout.
	 */
	protected void initializeLayout()
	{
		initializeGroupLayout();
		// initializeGridBagLayout();
	}


	protected void initializeGridBagLayout()
	{

		final GridBagLayout gbl = new GridBagLayout();
		final GridBagConstraints gbc = new GridBagConstraints();
		this.setLayout(gbl);

		LayoutExtensions.add(GridBagLayoutModel.builder().layoutComponent(lblKeySize).parent(this)
			.gridBagLayout(gbl).gridBagConstraints(gbc).anchor(GridBagConstraints.NORTHWEST)
			.fill(GridBagConstraints.BOTH)
			.insets(InsetsModel.builder().top(2).left(2).bottom(2).right(2).build()).gridx(0)
			.gridy(1).gridwidth(1).gridheight(1).weightx(100).weighty(100).build());

		LayoutExtensions.add(GridBagLayoutModel.builder().layoutComponent(lblPrivateKey)
			.parent(this).gridBagLayout(gbl).gridBagConstraints(gbc)
			.anchor(GridBagConstraints.NORTHWEST).fill(GridBagConstraints.BOTH)
			.insets(InsetsModel.builder().top(2).left(2).bottom(2).right(2).build()).gridx(1)
			.gridy(1).gridwidth(1).gridheight(1).weightx(100).weighty(100).build());

		LayoutExtensions.add(GridBagLayoutModel.builder().layoutComponent(lblPublicKey).parent(this)
			.gridBagLayout(gbl).gridBagConstraints(gbc).anchor(GridBagConstraints.NORTHWEST)
			.fill(GridBagConstraints.BOTH)
			.insets(InsetsModel.builder().top(2).left(2).bottom(2).right(2).build()).gridx(2)
			.gridy(1).gridwidth(1).gridheight(1).weightx(100).weighty(100).build());

		LayoutExtensions.add(GridBagLayoutModel.builder().layoutComponent(cmbKeySize).parent(this)
			.gridBagLayout(gbl).gridBagConstraints(gbc).anchor(GridBagConstraints.NORTHWEST)
			.fill(GridBagConstraints.HORIZONTAL)
			.insets(InsetsModel.builder().top(2).left(2).bottom(2).right(2).build()).gridx(0)
			.gridy(2).gridwidth(1).gridheight(1).weightx(100).weighty(100).build());

		LayoutExtensions.add(GridBagLayoutModel.builder().layoutComponent(txtPrivateKey)
			.parent(this).gridBagLayout(gbl).gridBagConstraints(gbc)
			.anchor(GridBagConstraints.NORTHWEST).fill(GridBagConstraints.BOTH)
			.insets(InsetsModel.builder().top(2).left(2).bottom(2).right(2).build()).gridx(1)
			.gridy(2).gridwidth(1).gridheight(1).weightx(100).weighty(100).build());

		LayoutExtensions.add(GridBagLayoutModel.builder().layoutComponent(txtPublicKey).parent(this)
			.gridBagLayout(gbl).gridBagConstraints(gbc).anchor(GridBagConstraints.NORTHWEST)
			.fill(GridBagConstraints.BOTH)
			.insets(InsetsModel.builder().top(2).left(2).bottom(2).right(2).build()).gridx(2)
			.gridy(2).ipady(140)// make this component tall
			.gridwidth(1).gridheight(1).weightx(100).weighty(100).build());

		LayoutExtensions.add(GridBagLayoutModel.builder().layoutComponent(btnGenerate).parent(this)
			.gridBagLayout(gbl).gridBagConstraints(gbc).anchor(GridBagConstraints.NORTHWEST)
			.fill(GridBagConstraints.HORIZONTAL)
			.insets(InsetsModel.builder().top(2).left(2).bottom(2).right(2).build()).gridx(0)
			.gridy(3).gridwidth(1).gridheight(1).weightx(100).weighty(100).build());

		LayoutExtensions.add(GridBagLayoutModel.builder().layoutComponent(btnClear).parent(this)
			.gridBagLayout(gbl).gridBagConstraints(gbc).anchor(GridBagConstraints.NORTHWEST)
			.fill(GridBagConstraints.HORIZONTAL)
			.insets(InsetsModel.builder().top(2).left(2).bottom(2).right(2).build()).gridx(0)
			.gridy(4).gridwidth(1).gridheight(1).weightx(100).weighty(100).build());

		LayoutExtensions.add(GridBagLayoutModel.builder().layoutComponent(btnSavePrivateKey)
			.parent(this).gridBagLayout(gbl).gridBagConstraints(gbc)
			.anchor(GridBagConstraints.NORTHWEST).fill(GridBagConstraints.BOTH)
			.insets(InsetsModel.builder().top(2).left(2).bottom(2).right(2).build()).gridx(1)
			.gridy(5).gridwidth(1).gridheight(1).weightx(100).weighty(100).build());

		LayoutExtensions.add(GridBagLayoutModel.builder().layoutComponent(btnSavePublicKey)
			.parent(this).gridBagLayout(gbl).gridBagConstraints(gbc)
			.anchor(GridBagConstraints.NORTHWEST).fill(GridBagConstraints.BOTH)
			.insets(InsetsModel.builder().top(2).left(2).bottom(2).right(2).build()).gridx(2)
			.gridy(5).gridwidth(1).gridheight(1).weightx(100).weighty(100).build());

	}

	protected void initializeGroupLayout()
	{
		final javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
		this.setLayout(layout);
		layout.setHorizontalGroup(layout.createParallelGroup(
			javax.swing.GroupLayout.Alignment.LEADING)
			.addGroup(layout
				.createSequentialGroup()
				.addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
					.addGroup(layout.createSequentialGroup().addGroup(layout
						.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
						.addGroup(layout.createSequentialGroup().addContainerGap().addGroup(layout
							.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
							.addComponent(cmbKeySize, 0, javax.swing.GroupLayout.DEFAULT_SIZE,
								Short.MAX_VALUE)
							.addComponent(btnGenerate, javax.swing.GroupLayout.DEFAULT_SIZE, 206,
								Short.MAX_VALUE)))
						.addGroup(layout.createSequentialGroup().addGap(21, 21, 21).addComponent(
							lblKeySize, javax.swing.GroupLayout.PREFERRED_SIZE, 147,
							javax.swing.GroupLayout.PREFERRED_SIZE))
						.addGroup(layout.createSequentialGroup().addContainerGap().addComponent(
							btnClear, javax.swing.GroupLayout.DEFAULT_SIZE,
							javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)))
						.addGap(18, 18, 18).addGroup(
							layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
								.addComponent(scpPrivateKey, javax.swing.GroupLayout.PREFERRED_SIZE,
									480, javax.swing.GroupLayout.PREFERRED_SIZE)
								.addComponent(lblPrivateKey, javax.swing.GroupLayout.PREFERRED_SIZE,
									147, javax.swing.GroupLayout.PREFERRED_SIZE)))
					.addGroup(layout.createSequentialGroup().addGap(542, 542, 542).addComponent(
						btnSavePrivateKey, javax.swing.GroupLayout.PREFERRED_SIZE, 174,
						javax.swing.GroupLayout.PREFERRED_SIZE)))
				.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 60,
					Short.MAX_VALUE)
				.addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
					.addGroup(javax.swing.GroupLayout.Alignment.TRAILING,
						layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
							.addComponent(lblPublicKey, javax.swing.GroupLayout.PREFERRED_SIZE, 147,
								javax.swing.GroupLayout.PREFERRED_SIZE)
							.addComponent(scpPublicKey, javax.swing.GroupLayout.PREFERRED_SIZE, 480,
								javax.swing.GroupLayout.PREFERRED_SIZE))
					.addComponent(btnSavePublicKey, javax.swing.GroupLayout.Alignment.TRAILING,
						javax.swing.GroupLayout.PREFERRED_SIZE, 174,
						javax.swing.GroupLayout.PREFERRED_SIZE))
				.addContainerGap(31, Short.MAX_VALUE)));
		layout
			.setVerticalGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(layout.createSequentialGroup().addGap(26, 26, 26)
					.addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
						.addComponent(lblPrivateKey, javax.swing.GroupLayout.PREFERRED_SIZE, 29,
							javax.swing.GroupLayout.PREFERRED_SIZE)
						.addComponent(lblKeySize, javax.swing.GroupLayout.PREFERRED_SIZE, 29,
							javax.swing.GroupLayout.PREFERRED_SIZE)
						.addComponent(lblPublicKey, javax.swing.GroupLayout.PREFERRED_SIZE, 29,
							javax.swing.GroupLayout.PREFERRED_SIZE))
					.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
					.addGroup(layout
						.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
						.addGroup(layout.createSequentialGroup()
							.addComponent(cmbKeySize, javax.swing.GroupLayout.PREFERRED_SIZE, 43,
								javax.swing.GroupLayout.PREFERRED_SIZE)
							.addGap(18, 18, 18)
							.addComponent(btnGenerate, javax.swing.GroupLayout.PREFERRED_SIZE, 41,
								javax.swing.GroupLayout.PREFERRED_SIZE)
							.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
							.addComponent(btnClear, javax.swing.GroupLayout.PREFERRED_SIZE, 41,
								javax.swing.GroupLayout.PREFERRED_SIZE))
						.addComponent(scpPrivateKey, javax.swing.GroupLayout.DEFAULT_SIZE, 265,
							Short.MAX_VALUE)
						.addComponent(scpPublicKey))
					.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 24,
						Short.MAX_VALUE)
					.addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
						.addComponent(btnSavePublicKey, javax.swing.GroupLayout.PREFERRED_SIZE, 41,
							javax.swing.GroupLayout.PREFERRED_SIZE)
						.addComponent(btnSavePrivateKey, javax.swing.GroupLayout.PREFERRED_SIZE, 41,
							javax.swing.GroupLayout.PREFERRED_SIZE))
					.addContainerGap()));
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
	}

	/**
	 * Callback method that can be overwritten to provide specific action for the on clear.
	 *
	 * @param actionEvent
	 *            the action event
	 */
	protected void onClear(final ActionEvent actionEvent)
	{
	}

	/**
	 * Callback method that can be overwritten to provide specific action for the on generate.
	 *
	 * @param actionEvent
	 *            the action event
	 */
	protected void onGenerate(final ActionEvent actionEvent)
	{
	}

}
