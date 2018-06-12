package excluder.views;

import excluder.ExtensionDetails;
import excluder.views.custom.ScrollableSidebar;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.net.URI;

public class Tab implements ActionListener {

    private JPanel tab;
    private JLabel title;
    private JLabel version;

    private JSplitPane splitPane;
    private JScrollPane optionScrollPane;
    private JScrollPane requestsScrollPane;
    private JPanel optionsWrapper;

    private DefaultListModel<String> similarRequestsModel = new DefaultListModel<>();
    private JList similarRequests;

    private JButton documentationButton;
    private JButton reportBugButton;

    private JLabel amountResponsesScanned;
    private JLabel amountUniqueResponsesFound;
    private JLabel amountSimilarResponsesFound;
    private JLabel amountAdditionalMilliseconds;

    public Tab() {
        this.title.setText(ExtensionDetails.TITLE);
        this.version.setText("Version " + ExtensionDetails.VERSION);

        this.splitPane.setBorder(BorderFactory.createMatteBorder(1, 0, 1, 0, Color.LIGHT_GRAY));
        this.optionScrollPane.setViewportView(new ScrollableSidebar(optionsWrapper));

        this.reportBugButton.addActionListener(this);
        this.documentationButton.addActionListener(this);

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

    @Override
    public void actionPerformed(ActionEvent e) {
        switch (e.getActionCommand()) {
            case "documentation":
                try {
                    Desktop.getDesktop().browse(new URI(ExtensionDetails.DOCUMENTATION_URL));
                } catch (Exception e1) {
                    e1.printStackTrace();
                }
                break;
            case "report-bug":
                try {
                    Desktop.getDesktop().browse(new URI(ExtensionDetails.REPORT_BUG_URL));
                } catch (Exception e1) {
                    e1.printStackTrace();
                }
                break;
        }
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
        amountAdditionalMilliseconds.setText("<html><b>~ " + newValue + "</b> additional milliseconds per request.</html>");
    }

}
