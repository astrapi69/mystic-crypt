package de.alpharogroup.mystic.crypt.actions;

import java.awt.event.ActionEvent;

import javax.swing.AbstractAction;
import javax.swing.JInternalFrame;

import de.alpharogroup.mystic.crypt.MainFrame;
import de.alpharogroup.mystic.crypt.panels.obfuscate.RulePanel;
import de.alpharogroup.swing.components.factories.JComponentFactory;
import de.alpharogroup.swing.utils.JInternalFrameExtensions;

/**
 * The class {@link NewObfuscationInternalFrameAction}.
 */
public class NewObfuscationInternalFrameAction extends AbstractAction {

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = 1L;

	/**
	 * Instantiates a new new action.
	 *
	 * @param name
	 *            the name
	 */
	public NewObfuscationInternalFrameAction(final String name) {
		super(name);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void actionPerformed(final ActionEvent e) {
		// create internal frame
		final JInternalFrame internalFrame = JComponentFactory.newInternalFrame("Obfuscation demo", true, true,
				true, true);
		final RulePanel component = new RulePanel();
		JInternalFrameExtensions.addComponentToFrame(internalFrame, component);

		JInternalFrameExtensions.addJInternalFrame(MainFrame.getInstance().getDesktopPane(), internalFrame);
	}

}