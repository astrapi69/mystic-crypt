package de.alpharogroup.mystic.crypt.panels;

import java.io.IOException;

import javax.swing.JFrame;

import de.alpharogroup.layout.CloseWindow;

public class EnDecryptPanelTest
{

	/**
	 * The main method.
	 *
	 * @param args the arguments
	 * @throws IOException
	 */
	public static void main(final String[] args) throws IOException {
		final JFrame frame = new JFrame();
		frame.addWindowListener(new CloseWindow());
		frame.setTitle("CryptographyPanel");

		final EnDecryptPanel pnlIconPanel = new EnDecryptPanel();
		frame.add( pnlIconPanel);
        frame.setBounds(0, 0, 1020, 250);
        frame.setVisible( true );
	}

}
