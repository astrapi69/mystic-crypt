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
package de.alpharogroup.mystic.crypt;

import javax.swing.JFrame;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.UnsupportedLookAndFeelException;

import de.alpharogroup.layout.ScreenSizeExtensions;
import de.alpharogroup.swing.laf.LookAndFeels;

public class MainApplication
{

	/**
	 * The main method.
	 *
	 * @param args
	 *            the arguments
	 */
	public static void main(final String[] args) {

		final MainFrame mainFrame = MainFrame.getInstance();
		final DesktopMenu menu = DesktopMenu.getInstance();
		mainFrame.setJMenuBar(menu.getMenubar());

		mainFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		mainFrame.setSize(ScreenSizeExtensions.getScreenWidth(), ScreenSizeExtensions.getScreenHeight());
		mainFrame.setVisible(true);
		mainFrame.getDesktopPane().getDesktopManager().activateFrame(mainFrame.getInternalFrame());
		mainFrame.getDesktopPane().getDesktopManager().maximizeFrame(mainFrame.getInternalFrame());
		mainFrame.getInternalFrame().toFront();

		// Set default look and feel...
		try {
			UIManager.setLookAndFeel(LookAndFeels.SYSTEM.getLookAndFeelName());
			SwingUtilities.updateComponentTreeUI(mainFrame);
			mainFrame.setCurrentLookAndFeels(LookAndFeels.SYSTEM);
		} catch (final ClassNotFoundException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (final InstantiationException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (final IllegalAccessException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (final UnsupportedLookAndFeelException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
	}
}
