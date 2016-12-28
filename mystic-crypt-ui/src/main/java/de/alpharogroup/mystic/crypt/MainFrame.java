package de.alpharogroup.mystic.crypt;

import javax.swing.JDesktopPane;
import javax.swing.JInternalFrame;
import javax.swing.JMenuBar;
import javax.swing.JToolBar;

import org.jdesktop.swingx.JXFrame;

//
//import de.alpharogroup.duplicate.files.controller.FindDuplicateFilesController;
//import de.alpharogroup.duplicate.files.gen.view.FindDuplicateFilesView;
//import de.alpharogroup.duplicate.files.utils.JInternalFrameExtensions;
import de.alpharogroup.swing.components.factories.JComponentFactory;
import de.alpharogroup.swing.desktoppane.SingletonDesktopPane;
import de.alpharogroup.swing.laf.LookAndFeels;
import de.alpharogroup.swing.utils.JInternalFrameExtensions;
import lombok.Getter;
import lombok.Setter;

/**
 * The Class MainFrame.
 */
@SuppressWarnings("serial")
public class MainFrame extends JXFrame {

	/** The instance. */
	private static MainFrame instance = new MainFrame();

	/** The desktop pane. */
	@Getter
	private final JDesktopPane desktopPane = SingletonDesktopPane.getInstance();

	/** The menubar. */
	@Getter
	private JMenuBar menubar;

	/** The toolbar. */
	@Getter
	private JToolBar toolbar;

	/** The internal frame. */
	@Getter
	private JInternalFrame internalFrame;

	/** The current look and feels. */
	@Getter
	@Setter
	private LookAndFeels currentLookAndFeels = LookAndFeels.SYSTEM;

	/**
	 * Gets the single instance of MainFrame.
	 *
	 * @return single instance of MainFrame
	 */
	public static MainFrame getInstance() {
		return instance;
	}

	/**
	 * Instantiates a new main frame.
	 */
	private MainFrame() {
		super("Find duplicate files");
		initComponents();
	}

	/**
	 * Inits the components.
	 */
	private void initComponents() {

		toolbar = new JToolBar(); // create the tool bar
		setJMenuBar(menubar);
		setToolBar(toolbar);

		// create internal frame
		internalFrame = JComponentFactory.newInternalFrame("Random generator", true, true, true, true);

//		final FindDuplicateFilesView view = new FindDuplicateFilesView(new FindDuplicateFilesController());
//		JInternalFrameExtensions.setViewAndControllerForJInternalFrame(internalFrame, view);

		JInternalFrameExtensions.addJInternalFrame(desktopPane, internalFrame);

		getContentPane().add(desktopPane);

	}

}
