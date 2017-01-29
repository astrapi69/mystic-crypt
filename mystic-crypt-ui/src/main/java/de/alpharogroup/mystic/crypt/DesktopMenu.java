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

import java.awt.Window;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.net.URL;

import javax.help.CSH;
import javax.help.DefaultHelpBroker;
import javax.help.HelpSet;
import javax.help.HelpSetException;
import javax.help.WindowPresentation;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;

import org.apache.log4j.Logger;

import de.alpharogroup.lang.ClassExtensions;
import de.alpharogroup.mystic.crypt.actions.NewKeyGenerationInternalFrameAction;
import de.alpharogroup.mystic.crypt.actions.NewObfuscationInternalFrameAction;
import de.alpharogroup.mystic.crypt.actions.OpenBrowserToDonateAction;
import de.alpharogroup.mystic.crypt.actions.ShowHelpDialogAction;
import de.alpharogroup.mystic.crypt.actions.ShowLicenseFrameAction;
import de.alpharogroup.swing.actions.ExitApplicationAction;
import de.alpharogroup.swing.laf.actions.LookAndFeelMetalAction;
import de.alpharogroup.swing.laf.actions.LookAndFeelMotifAction;
import de.alpharogroup.swing.laf.actions.LookAndFeelSystemAction;
import de.alpharogroup.swing.menu.MenuExtensions;
import lombok.Getter;
import lombok.Setter;

/**
 * The Class DesktopMenu.
 */
public class DesktopMenu {

	/** The Constant logger. */
	private static final Logger logger = Logger.getLogger(DesktopMenu.class.getName());

	/** The JMenuBar from the DesktopMenu. */
	@Getter
	private final JMenuBar menubar;

	/** The file menu. */
	@Getter
	private final JMenu fileMenu;

	/** The look and feel menu. */
	@Getter
	private final JMenu lookAndFeelMenu;

	/** The help menu. */
	@Getter
	private final JMenu helpMenu;

	/** The help window. */
	@Getter
	@Setter
	private Window helpWindow;

	/** The instance. */
	private static DesktopMenu instance = new DesktopMenu();

	/**
	 * Gets the single instance of DesktopMenu.
	 *
	 * @return single instance of DesktopMenu
	 */
	public static DesktopMenu getInstance() {
		return instance;
	}

	/**
	 * Instantiates a new desktop menu.
	 */
	private DesktopMenu() {
		menubar = new JMenuBar();
		fileMenu = newFileMenu(new ActionListener() {
			@Override
			public void actionPerformed(final ActionEvent e) {
				logger.debug("filemenu");
			}
		});

		lookAndFeelMenu = createLookAndFeelMenu(new ActionListener() {
			@Override
			public void actionPerformed(final ActionEvent e) {
				logger.debug("Look and Feel menu");
			}
		});

		helpMenu = createHelpMenu(new ActionListener() {
			@Override
			public void actionPerformed(final ActionEvent e) {
				logger.debug("Help menu");
			}
		});

		menubar.add(fileMenu);
		menubar.add(lookAndFeelMenu);
		menubar.add(helpMenu);
	}

	/**
	 * Creates the file menu.
	 *
	 * @param listener
	 *            the listener
	 *
	 * @return the j menu
	 */
	private JMenu newFileMenu(final ActionListener listener) {
		final JMenu fileMenu = new JMenu("File");
		fileMenu.setMnemonic('F');
		JMenuItem jmi;

		// New key generation
		jmi = new JMenuItem("New key generation", 'K');
		 jmi.addActionListener(new NewKeyGenerationInternalFrameAction("New key generation"));
		MenuExtensions.setCtrlAccelerator(jmi, 'K');
		fileMenu.add(jmi);

		// Separator
		fileMenu.addSeparator();

		// New obfuscation
		jmi = new JMenuItem("New obfuscation", 'O');
		 jmi.addActionListener(new NewObfuscationInternalFrameAction("New Obfuscation"));
		MenuExtensions.setCtrlAccelerator(jmi, 'O');
		fileMenu.add(jmi);

		// Separator
		fileMenu.addSeparator();

		// Save
//		JMenuItem jmiSave;
//		jmiSave = new JMenuItem("Save", 'S');
//		jmiSave.addActionListener(listener);
//		MenuExtensions.setCtrlAccelerator(jmiSave, 'S');
//		jmiSave.setEnabled(false);
//		fileMenu.add(jmiSave);

		// Separator
//		fileMenu.addSeparator();

		// Save as
//		JMenuItem jmiSaveAs;
//		jmiSaveAs = new JMenuItem("Save as", 'a');
//		jmiSaveAs.addActionListener(listener);
//		jmiSaveAs.setEnabled(false);
//		fileMenu.add(jmiSaveAs);

		// Separator
//		fileMenu.addSeparator();

		// Configuration
//		JMenuItem jmiPrint;
//		jmiPrint = new JMenuItem("Print", 'r');
//		jmiPrint.addActionListener(listener);
//		jmiPrint.setEnabled(false);
//		fileMenu.add(jmiPrint);

		// Separator
//		fileMenu.addSeparator();

		// Configuration
//		JMenuItem jmiConfiguration;
//		jmiConfiguration = new JMenuItem("Configuration", 'C');
//		jmiConfiguration.addActionListener(listener);
//		jmiConfiguration.setEnabled(false);
//		fileMenu.add(jmiConfiguration);

		// Separator
//		fileMenu.addSeparator();

		// Configuration
		JMenuItem jmiExit;
		jmiExit = new JMenuItem("Exit", 'E');
		jmiExit.addActionListener(new ExitApplicationAction("Exit"));
		fileMenu.add(jmiExit);

		return fileMenu;
	}

	/**
	 * Creates the look and feel menu.
	 *
	 * @param listener
	 *            the listener
	 * @return the j menu
	 */
	private JMenu createLookAndFeelMenu(final ActionListener listener) {

		final JMenu menuLookAndFeel = new JMenu("Look and Feel");
		menuLookAndFeel.setMnemonic('L');

		// Look and Feel JMenuItems
		// Metal default Metal theme
		JMenuItem jmiLafMetal;
		jmiLafMetal = new JMenuItem("Metal", 'm'); //$NON-NLS-1$
		MenuExtensions.setCtrlAccelerator(jmiLafMetal, 'M');
		jmiLafMetal.addActionListener(new LookAndFeelMetalAction("Metal", MainFrame.getInstance()));
		menuLookAndFeel.add(jmiLafMetal);
		// Metal Ocean theme
		JMenuItem jmiLafOcean;
		jmiLafOcean = new JMenuItem("Ocean", 'o'); //$NON-NLS-1$
		MenuExtensions.setCtrlAccelerator(jmiLafOcean, 'O');
		jmiLafOcean.addActionListener(new LookAndFeelMetalAction("Ocean", MainFrame.getInstance()));
		menuLookAndFeel.add(jmiLafOcean);
		// Motif
		JMenuItem jmiLafMotiv;
		jmiLafMotiv = new JMenuItem("Motif", 't'); //$NON-NLS-1$
		MenuExtensions.setCtrlAccelerator(jmiLafMotiv, 'T');
		jmiLafMotiv.addActionListener(new LookAndFeelMotifAction("Motif", MainFrame.getInstance()));
		menuLookAndFeel.add(jmiLafMotiv);
		// Windows
		JMenuItem jmiLafSystem;
		jmiLafSystem = new JMenuItem("System", 'd'); //$NON-NLS-1$
		MenuExtensions.setCtrlAccelerator(jmiLafSystem, 'W');
		jmiLafSystem.addActionListener(new LookAndFeelSystemAction("System", MainFrame.getInstance()));
		menuLookAndFeel.add(jmiLafSystem);

		return menuLookAndFeel;

	}

	/**
	 * Creates the help menu.
	 *
	 * @param listener
	 *            the listener
	 * @return the j menu
	 */
	private JMenu createHelpMenu(final ActionListener listener) {
		// Help menu
		final JMenu menuHelp = new JMenu("Help"); //$NON-NLS-1$
		menuHelp.setMnemonic('H');

		// Help JMenuItems
		// Help content
		final JMenuItem mihHelpContent = new JMenuItem("Content", 'c'); //$NON-NLS-1$
		MenuExtensions.setCtrlAccelerator(mihHelpContent, 'H');

		menuHelp.add(mihHelpContent);
		// found bug with the javax.help
		// Exception in thread "main" java.lang.SecurityException: no manifiest
		// section for signature file entry
		// com/sun/java/help/impl/TagProperties.class
		// Solution is to remove the rsa files from the jar

		final HelpSet hs = getHelpSet();
		final DefaultHelpBroker helpBroker = (DefaultHelpBroker) hs.createHelpBroker();
		final WindowPresentation pres = helpBroker.getWindowPresentation();
		pres.createHelpWindow();
		helpWindow = pres.getHelpWindow();

		helpWindow.setLocationRelativeTo(null);

		try {
			UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
		} catch (final Exception e1) {
			e1.printStackTrace();
		}
		SwingUtilities.updateComponentTreeUI(helpWindow);

		// 2. assign help to components
		CSH.setHelpIDString(mihHelpContent, "Overview");
		// 3. handle events
		final CSH.DisplayHelpFromSource displayHelpFromSource = new CSH.DisplayHelpFromSource(helpBroker);
		mihHelpContent.addActionListener(displayHelpFromSource);

		mihHelpContent.addActionListener(new ShowHelpDialogAction("Content"));

		// Donate
		final JMenuItem mihDonate = new JMenuItem(Messages.getString("com.find.duplicate.files.menu.item.donate")); //$NON-NLS-1$

		mihDonate.addActionListener(new OpenBrowserToDonateAction("Donate"));
		menuHelp.add(mihDonate);

		// Licence
		final JMenuItem mihLicence = new JMenuItem("Licence"); //$NON-NLS-1$
		mihLicence.addActionListener(new ShowLicenseFrameAction("Licence"));
		menuHelp.add(mihLicence);
		// Info
		final JMenuItem mihInfo = new JMenuItem("Info", 'i'); //$NON-NLS-1$
		MenuExtensions.setCtrlAccelerator(mihInfo, 'I');
		// TODO add action
				// mihInfo.addActionListener(new ShowInfoDialogAction("Info"));
		menuHelp.add(mihInfo);

		return menuHelp;
	}

	/**
	 * Gets the help set.
	 *
	 * @return the help set
	 */
	public HelpSet getHelpSet() {
		HelpSet hs = null;
		final String filename = "simple-hs.xml";
		final String path = "help/" + filename;
		URL hsURL;
		if (hs == null) {
			hsURL = ClassExtensions.getResource(path);
			try {
				hs = new HelpSet(ClassExtensions.getClassLoader(), hsURL);
			} catch (final HelpSetException e) {
				e.printStackTrace();
			}
		}
		return hs;
	}

}