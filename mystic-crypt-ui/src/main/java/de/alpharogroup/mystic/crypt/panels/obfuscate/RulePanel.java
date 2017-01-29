package de.alpharogroup.mystic.crypt.panels.obfuscate;

import java.awt.event.ActionEvent;

import javax.swing.JPanel;

import de.alpharogroup.mystic.crypt.panels.EnDecryptPanel;
import net.miginfocom.swing.MigLayout;

public class RulePanel extends JPanel {

	private static final long serialVersionUID = 1L;
	private SimpleRulePanel simpleRulePanel;
	private SimpleRuleTablePanel simpleRuleTablePanel;
	private EnDecryptPanel enDecryptPanel;

    /**
     * Creates new form RulePanel
     */
    public RulePanel() {
    	initialize();
    }
	/**
	 * Initialize Panel.
	 */
	protected void initialize()
	{
		initializeComponents();
		initializeLayout();
	}

	protected void initializeComponents()
	{
		simpleRulePanel = new SimpleRulePanel();
		simpleRuleTablePanel = new SimpleRuleTablePanel();

		enDecryptPanel = new EnDecryptPanel()
		{
			private static final long serialVersionUID = 1L;

			@Override
			protected void onDecrypt(final ActionEvent actionEvent)
			{
				RulePanel.this.onDecrypt(actionEvent);
			}

			@Override
			protected void onEncrypt(final ActionEvent actionEvent)
			{
				RulePanel.this.onEncrypt(actionEvent);
			}
		};
	}
	protected void onEncrypt(final ActionEvent actionEvent)
	{
		// TODO Auto-generated method stub

	}
	protected void onDecrypt(final ActionEvent actionEvent)
	{
		// TODO Auto-generated method stub

	}
	/**
	 * Initialize layout.
	 */
	protected void initializeLayout()
	{
		initializeMigLayout();
	}

	protected void initializeMigLayout()
	{
		setLayout(new MigLayout());
		add(simpleRulePanel, "wrap");
		add(simpleRuleTablePanel, "wrap");
		add(enDecryptPanel);
	}

}
