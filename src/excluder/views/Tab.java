package excluder.views;

import excluder.ExtensionDebugger;
import excluder.ExtensionDetails;
import excluder.adapters.NodesAdapter;
import excluder.helpers.FileHelper;
import excluder.sets.OrderedHashSet;
import excluder.views.custom.ScrollableSidebar;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.FileWriter;
import java.net.URI;
import java.util.stream.Collectors;

public class Tab extends MouseAdapter implements ActionListener, MouseListener {

    private TabListener listener;

    private JPanel tab;
    private JLabel title;

    private JLabel versionLabel;
    private JLabel documentationLabel;
    private JLabel bugLabel;

    private JSplitPane splitPane;
    private JScrollPane optionScrollPane;
    private JScrollPane requestsScrollPane;
    private JPanel optionsWrapper;

    private JList similarRequests;

    private JButton exportSimilarButton;
    private JButton exportUniqueButton;
    private JButton cleanGraphButton;

    private JLabel amountResponsesScanned;
    private JLabel amountUniqueResponsesFound;
    private JLabel amountSimilarResponsesFound;
    private JLabel amountAdditionalMilliseconds;

    public interface TabListener {
        OrderedHashSet getUniqueRequests();
        OrderedHashSet getSimilarRequests();
        NodesAdapter getNodesAdapter();
        void cleanGraph();
    }

    public Tab(TabListener listener) {
        this.listener = listener;

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
        this.cleanGraphButton.addActionListener(this);

        this.similarRequests.setModel(listener.getNodesAdapter());
    }

    public JPanel getPanel() {
        return this.tab;
    }

    public JPanel getOptionsWrapper() {
        return this.optionsWrapper;
    }

    public void setAmountResponsesScanned(int newValue) {
        this.amountResponsesScanned.setText("<html><b>" + newValue + "</b> responses scanned.</html>");
    }
    public void setAmountUniqueResponsesFound(int newValue) {
        this.amountUniqueResponsesFound.setText("<html><b>" + newValue + "</b> unique responses found.</html>");
    }

    public void setAmountSimilarResponsesFound(int newValue) {
        this.amountSimilarResponsesFound.setText("<html><b>" + newValue + "</b> similar responses found.</html>");
    }

    public void setAmountAdditionalMilliseconds(long newValue) {
        this.amountAdditionalMilliseconds.setText("<html><b>~" + newValue + "</b> additional milliseconds per request.</html>");
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        switch (e.getActionCommand()) {
            case "exportSimilar": exportSimilar(); break;
            case "exportUnique": exportUnique(); break;
            case "cleanGraph": cleanGraph(); break;
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

    private void exportSimilar() {
        JFileChooser chooser = new JFileChooser();
        int returnValue = chooser.showSaveDialog(null);

        if (returnValue == JFileChooser.APPROVE_OPTION) {
            try (FileWriter fw = new FileWriter(chooser.getSelectedFile())) {
                String result = (String) this.listener.getSimilarRequests()
                        .stream()
                        .map(i -> i.toString())
                        .collect(Collectors.joining("\n"));

                fw.write(result);
            } catch (Exception e) {
                ExtensionDebugger.error(e);
            }
        }
    }

    private void exportUnique() {
        JFileChooser chooser = new JFileChooser();
        int returnValue = chooser.showSaveDialog(null);

        if (returnValue == JFileChooser.APPROVE_OPTION) {
            try (FileWriter fw = new FileWriter(chooser.getSelectedFile())) {
                String result = (String) this.listener.getUniqueRequests()
                        .stream()
                        .map(i -> i.toString())
                        .collect(Collectors.joining("\n"));

                fw.write(result);
            } catch (Exception e) {
                ExtensionDebugger.error(e);
            }
        }
    }

    private void cleanGraph() {
        int dialogResult = JOptionPane.showConfirmDialog(
                null,
                "Are you sure you want to discard the current knowledge base?",
                "Warning",
                JOptionPane.YES_NO_OPTION
        );

        if (dialogResult == JOptionPane.YES_OPTION) {
            this.listener.cleanGraph();

            setAmountResponsesScanned(0);
            setAmountUniqueResponsesFound(0);
            setAmountSimilarResponsesFound(0);
            setAmountAdditionalMilliseconds(0);
        }
    }

}
