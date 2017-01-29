package de.alpharogroup.mystic.crypt.actions;

import java.awt.event.ActionEvent;

import javax.swing.AbstractAction;
import javax.swing.JInternalFrame;

import de.alpharogroup.mystic.crypt.MainFrame;
import de.alpharogroup.mystic.crypt.panels.GenerateKeysPanel;
import de.alpharogroup.swing.components.factories.JComponentFactory;
import de.alpharogroup.swing.utils.JInternalFrameExtensions;

/**
 * The class {@link NewKeyGenerationInternalFrameAction}.
 */
public class NewKeyGenerationInternalFrameAction extends AbstractAction {

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = 1L;

	/**
	 * Instantiates a new new action.
	 *
	 * @param name
	 *            the name
	 */
	public NewKeyGenerationInternalFrameAction(final String name) {
		super(name);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void actionPerformed(final ActionEvent e) {
		// create internal frame
		final JInternalFrame internalFrame = JComponentFactory.newInternalFrame("Key generation demo", true, true,
				true, true);

		final GenerateKeysPanel component = new GenerateKeysPanel();
		JInternalFrameExtensions.addComponentToFrame(internalFrame, component);
		JInternalFrameExtensions.addJInternalFrame(MainFrame.getInstance().getDesktopPane(), internalFrame);
	}

}