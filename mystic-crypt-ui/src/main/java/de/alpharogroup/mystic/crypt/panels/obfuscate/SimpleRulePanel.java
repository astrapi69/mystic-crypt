package de.alpharogroup.mystic.crypt.panels.obfuscate;

import java.awt.event.ActionEvent;

import javax.swing.GroupLayout;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.LayoutStyle;

import lombok.Getter;

@Getter
public class SimpleRulePanel extends JPanel {

	private static final long serialVersionUID = 1L;
	private JButton btnAdd;
    private JLabel lblKeyRule;
    private JLabel lblOriginalChar;
    private JLabel lblReplaceWith;
    private JTextField txtOriginalChar;
    private JTextField txtRelpaceWith;
    /**
     * Creates new form SimpleRulePanel
     */
    public SimpleRulePanel() {
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

	private void initializeComponents() {

        txtOriginalChar = new JTextField();
        lblOriginalChar = new JLabel();
        txtRelpaceWith = new JTextField();
        btnAdd = new JButton();
        lblReplaceWith = new JLabel();
        lblKeyRule = new JLabel();

        lblOriginalChar.setText("Original Character");

        btnAdd.addActionListener(actionEvent -> onAdd(actionEvent));
        btnAdd.setText("Add");

        lblReplaceWith.setText("Replace with");

        lblKeyRule.setText("KeyRule");
    }

    protected void onAdd(final ActionEvent actionEvent)
	{
	}

	protected void initializeGroupLayout()
	{



        final GroupLayout layout = new GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(lblKeyRule)
                        .addGap(0, 0, Short.MAX_VALUE))
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                            .addComponent(lblOriginalChar)
                            .addComponent(txtOriginalChar, GroupLayout.PREFERRED_SIZE, 480, GroupLayout.PREFERRED_SIZE))
                        .addGap(53, 53, 53)
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(txtRelpaceWith, GroupLayout.PREFERRED_SIZE, 480, GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED, 48, Short.MAX_VALUE)
                                .addComponent(btnAdd, GroupLayout.PREFERRED_SIZE, 170, GroupLayout.PREFERRED_SIZE))
                            .addComponent(lblReplaceWith))
                        .addContainerGap())))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(10, 10, 10)
                .addComponent(lblKeyRule)
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(lblOriginalChar)
                    .addComponent(lblReplaceWith))
                .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(txtOriginalChar, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                    .addComponent(txtRelpaceWith, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                    .addComponent(btnAdd))
                .addContainerGap(29, Short.MAX_VALUE))
        );
	}

}