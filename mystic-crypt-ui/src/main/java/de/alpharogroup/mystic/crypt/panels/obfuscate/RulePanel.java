package de.alpharogroup.mystic.crypt.panels.obfuscate;

import java.awt.event.ActionEvent;
import java.util.Map;

import javax.swing.JPanel;

import de.alpharogroup.collections.pairs.KeyValuePair;
import de.alpharogroup.crypto.keyrules.Obfuscatable;
import de.alpharogroup.crypto.keyrules.Obfuscator;
import de.alpharogroup.crypto.keyrules.SimpleKeyRule;
import de.alpharogroup.mystic.crypt.panels.EnDecryptPanel;
import lombok.Getter;
import net.miginfocom.swing.MigLayout;

@Getter
public class RulePanel extends JPanel
{

	private static final long serialVersionUID = 1L;
	private SimpleRulePanel simpleRulePanel;
	private SimpleRuleTablePanel simpleRuleTablePanel;
	private EnDecryptPanel enDecryptPanel;
	private ObfuscationModel model;

	/**
	 * Creates new form RulePanel
	 */
	public RulePanel()
	{
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
		model = ObfuscationModel.builder().keyRulesTableModel(KeyRulesTableModel.builder().build())
			.build();
		simpleRulePanel = new SimpleRulePanel()
		{
			private static final long serialVersionUID = 1L;

			@Override
			protected void onAdd(final ActionEvent actionEvent)
			{
				RulePanel.this.onAdd(actionEvent);
			}
		};
		simpleRuleTablePanel = new SimpleRuleTablePanel(model);

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
		enDecryptPanel.getBtnEncrypt().setText("Obfuscate >");
		enDecryptPanel.getBtnDecrypt().setText("< Disentangle");
	}


	protected void onAdd(final ActionEvent actionEvent)
	{
		final String origChar = simpleRulePanel.getTxtOriginalChar().getText();
		final String replaceWith = simpleRulePanel.getTxtRelpaceWith().getText();
		model.getKeyRulesTableModel()
			.add(KeyValuePair.<String, String> builder()
				.key(origChar)
				.value(replaceWith)
				.build());
		simpleRulePanel.getTxtOriginalChar().setText("");
		simpleRulePanel.getTxtRelpaceWith().setText("");
	}


	protected void onEncrypt(final ActionEvent actionEvent)
	{
		final String toObfuscatedString = getEnDecryptPanel().getTxtToEncrypt().getText();
		final Map<String, String> keymap = model.getKeyRulesTableModel().toMap();
		// create the rule
		final SimpleKeyRule replaceKeyRule = new SimpleKeyRule(keymap);
		// obfuscate the key
		final Obfuscatable obfuscator = new Obfuscator(replaceKeyRule, toObfuscatedString);
		model.setObfuscator(obfuscator);
		final String result = model.getObfuscator().obfuscate();
		getEnDecryptPanel().getTxtEncrypted().setText(result);
		getEnDecryptPanel().getTxtToEncrypt().setText("");
	}

	protected void onDecrypt(final ActionEvent actionEvent)
	{
		final String disentangledKey = model.getObfuscator().disentangle();
		getEnDecryptPanel().getTxtToEncrypt().setText(disentangledKey);
		getEnDecryptPanel().getTxtEncrypted().setText("");
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
