package excluder.views;

import excluder.ExtensionDebugger;
import excluder.ExtensionDetails;
import excluder.views.custom.ScrollableSidebar;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.net.URI;

public class Tab extends MouseAdapter implements ActionListener, MouseListener {

    private JPanel tab;
    private JLabel title;

    private JLabel versionLabel;
    private JLabel documentationLabel;
    private JLabel bugLabel;

    private JSplitPane splitPane;
    private JScrollPane optionScrollPane;
    private JScrollPane requestsScrollPane;
    private JPanel optionsWrapper;

    private DefaultListModel<String> similarRequestsModel = new DefaultListModel<>();
    private JList similarRequests;

    private JButton exportSimilarButton;
    private JButton exportUniqueButton;

    private JLabel amountResponsesScanned;
    private JLabel amountUniqueResponsesFound;
    private JLabel amountSimilarResponsesFound;
    private JLabel amountAdditionalMilliseconds;

    public Tab() {
        this.title.setText(ExtensionDetails.TITLE);

        this.versionLabel.setText("Release v" + ExtensionDetails.VERSION + ".");
        this.versionLabel.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        this.versionLabel.addMouseListener(this);

        this.documentationLabel.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        this.documentationLabel.addMouseListener(this);

        this.bugLabel.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        this.bugLabel.addMouseListener(this);

        this.splitPane.setBorder(BorderFactory.createMatteBorder(1, 0, 1, 0, Color.LIGHT_GRAY));
        this.optionScrollPane.setViewportView(new ScrollableSidebar(optionsWrapper));

        this.exportSimilarButton.addActionListener(this);
        this.exportUniqueButton.addActionListener(this);

        this.similarRequests.setModel(this.similarRequestsModel);
    }

    public JPanel getPanel() {
        return this.tab;
    }

    public DefaultListModel<String> getSimilarRequestsModel() {
        return this.similarRequestsModel;
    }

    public JPanel getOptionsWrapper() {
        return this.optionsWrapper;
    }

    public void setAmountResponsesScanned(int newValue) {
        amountResponsesScanned.setText("<html><b>" + newValue + "</b> responses scanned.</html>");
    }
    public void setAmountUniqueResponsesFound(int newValue) {
        amountUniqueResponsesFound.setText("<html><b>" + newValue + "</b> unique responses found.</html>");
    }

    public void setAmountSimilarResponsesFound(int newValue) {
        amountSimilarResponsesFound.setText("<html><b>" + newValue + "</b> similar responses found.</html>");
    }

    public void setAmountAdditionalMilliseconds(long newValue) {
        amountAdditionalMilliseconds.setText("<html><b>~" + newValue + "</b> additional milliseconds per request.</html>");
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        switch (e.getActionCommand()) {
            case "exportSimilar":

                break;
            case "exportUnique":

                break;
        }
    }

    @Override
    public void mouseClicked(MouseEvent e) {
        if (e.getSource() instanceof JLabel) {
            JLabel label = (JLabel) e.getSource();

            if (label == versionLabel) {
                try {
                    Desktop.getDesktop().browse(new URI(ExtensionDetails.VERSION_URL + "/v" + ExtensionDetails.VERSION));
                } catch (Exception e1) {
                    e1.printStackTrace();
                }
            } else if (label == documentationLabel) {
                try {
                    Desktop.getDesktop().browse(new URI(ExtensionDetails.DOCUMENTATION_URL));
                } catch (Exception e1) {
                    e1.printStackTrace();
                }
            } else if (label == bugLabel) {
                try {
                    Desktop.getDesktop().browse(new URI(ExtensionDetails.REPORT_BUG_URL));
                } catch (Exception e1) {
                    e1.printStackTrace();
                }
            }
        }
    }

}
