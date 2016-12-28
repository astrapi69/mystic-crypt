package de.alpharogroup.mystic.crypt.actions;

import de.alpharogroup.mystic.crypt.MainFrame;
import de.alpharogroup.swing.actions.OpenBrowserAction;

/**
 * The Class OpenBrowserToDonateAction.
 */
public class OpenBrowserToDonateAction extends OpenBrowserAction
{

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = 1L;
	/** The Constant URL_TO_DONATE. */
	public static final String URL_TO_DONATE = "http://sourceforge.net/donate/index.php?group_id=207406";

	/**
	 * Instantiates a new open browser to donate action.
	 *
	 * @param name
	 *            the name
	 */
	public OpenBrowserToDonateAction(final String name)
	{
		super(name, MainFrame.getInstance(), URL_TO_DONATE);
	}

}