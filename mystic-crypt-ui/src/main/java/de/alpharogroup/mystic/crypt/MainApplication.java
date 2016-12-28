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
