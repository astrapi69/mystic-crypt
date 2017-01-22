package de.alpharogroup.mystic.crypt.panels;

import java.io.IOException;

import javax.swing.JFrame;

import de.alpharogroup.layout.CloseWindow;

public class GenerateKeysPanelTest
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

		final GenerateKeysPanel panel = new GenerateKeysPanel();
		frame.add( panel);
        frame.setBounds(0, 0, 1280, 650);
        frame.setVisible( true );
	}

}
