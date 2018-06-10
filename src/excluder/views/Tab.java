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
    private JScrollPane scrollPane;
    private JPanel optionsWrapper;
    private JPanel details;

    private JList similarRequests;

    private JButton documentationButton;
    private JButton reportBugButton;

    public Tab() {
        this.title.setText(ExtensionDetails.TITLE);
        this.version.setText("Version " + ExtensionDetails.VERSION);

        this.splitPane.setBorder(BorderFactory.createMatteBorder(1, 0, 1, 0, Color.LIGHT_GRAY));
        this.details.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, Color.LIGHT_GRAY));

        this.scrollPane.setViewportView(new ScrollableSidebar(optionsWrapper));

        this.reportBugButton.addActionListener(this);
        this.documentationButton.addActionListener(this);
    }

    public JPanel getPanel() {
        return this.tab;
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
}
