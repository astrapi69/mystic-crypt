package de.alpharogroup.mystic.crypt.panels.obfuscate;

import javax.swing.GroupLayout;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.LayoutStyle;

import de.alpharogroup.collections.pairs.KeyValuePair;
import de.alpharogroup.swing.GenericJTable;

public class SimpleRuleTablePanel extends JPanel {

	private static final long serialVersionUID = 1L;
	private JLabel lblKeyRules;
    private JScrollPane scpKeyRules;
    private GenericJTable<KeyValuePair<String, String>> tblKeyRules;

    public SimpleRuleTablePanel() {
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

	/**
	 * Initialize layout.
	 */
	protected void initializeLayout()
	{
		initializeGroupLayout();
	}

	protected void initializeComponents() {

        scpKeyRules = new JScrollPane();
        tblKeyRules = new GenericJTable<>(KeyRulesTableModel.builder().build());
        lblKeyRules = new JLabel();

        scpKeyRules.setViewportView(tblKeyRules);

        lblKeyRules.setText("Table of key rules for obfuscate");
    }

    protected void initializeGroupLayout()
	{


        final GroupLayout layout = new GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(28, 28, 28)
                .addComponent(lblKeyRules)
                .addContainerGap(GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(scpKeyRules, GroupLayout.DEFAULT_SIZE, 1231, Short.MAX_VALUE)
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addContainerGap(31, Short.MAX_VALUE)
                .addComponent(lblKeyRules)
                .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(scpKeyRules, GroupLayout.PREFERRED_SIZE, 189, GroupLayout.PREFERRED_SIZE)
                .addGap(32, 32, 32))
        );
	}

}
