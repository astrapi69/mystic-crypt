package de.alpharogroup.mystic.crypt.panels;

import java.awt.event.ActionEvent;

import javax.swing.GroupLayout;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.LayoutStyle;

public class EnDecryptPanel extends JPanel
{

	private static final long serialVersionUID = 1L;

	private JButton btnDecrypt;
	private JButton btnEncrypt;
	private JLabel lblEncrypted;
	private JLabel lblToEncrypt;
	private JScrollPane scpEncrypted;
	private JScrollPane scpToEncrypt;
	private JTextArea txtEncrypted;
	private JTextArea txtToEncrypt;

	public EnDecryptPanel()
	{
		initialize();
	}


	protected void initialize()
	{
		initComponents();
		initializeLayout();
	}


	protected void initComponents()
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

		btnDecrypt.setText("< Decrypt");
		btnDecrypt.addActionListener(actionEvent -> onDecrypt(actionEvent));

		txtEncrypted.setColumns(20);
		txtEncrypted.setRows(5);
		scpEncrypted.setViewportView(txtEncrypted);

		lblEncrypted.setText("Text is encrypted");

	}

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

	protected void onDecrypt(final ActionEvent evt)
	{
		// TODO add your handling code here:
		System.out.println("onDecrypt");
	}


	protected void onEncrypt(final ActionEvent evt)
	{
		// TODO add your handling code here:
		System.out.println("onEncrypt");

	}

}