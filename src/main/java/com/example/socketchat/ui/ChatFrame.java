package com.example.socketchat.ui;

import com.example.socketchat.model.BroadcastAddress;
import com.example.socketchat.model.ChatMessage;
import com.example.socketchat.service.BroadcastAddressProvider;
import com.example.socketchat.service.UdpBroadcastService;
import com.google.inject.Inject;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

public final class ChatFrame extends JFrame {
    private static final Color APP_BG = new Color(0x0f1117);
    private static final Color TOP_BG = new Color(0x171d28);
    private static final Color INPUT_BG = new Color(0x20293a);
    private static final Color BORDER = new Color(0x2b3342);
    private static final Color MUTED = new Color(0x7184aa);
    private static final Color TEXT = new Color(0x93a4c9);
    private static final Color BLUE = new Color(0x3b82f6);
    private static final Color GREEN = new Color(0x19d59f);
    private static final Color SELECTED = new Color(0x172541);
    private static final Font MONO = new Font(Font.MONOSPACED, Font.PLAIN, 12);
    private static final Font LABEL = new Font(Font.MONOSPACED, Font.PLAIN, 11);

    @Inject
    private BroadcastAddressProvider addressProvider;
    @Inject
    private UdpBroadcastService udpService;
    private final JTextField addressField = new JTextField();
    private final JTextField portField = new JTextField("9000");
    private final JCheckBox startCheck = new JCheckBox();
    private final JLabel statusLabel = new JLabel("OFFLINE");
    private final JList<BroadcastAddress> addressList = new JList<>();
    private final JTextArea messages = new JTextArea();
    private final JTextField inputField = new JTextField();
    private final DateTimeFormatter timeFormat = DateTimeFormatter.ofPattern("HH:mm:ss.SSS");

    public ChatFrame() {
        configureFrame();
        installLook();
        buildLayout();
    }

    public void initialize() {
        bindEvents();
        loadAddresses();
        startListening();
    }

    private void configureFrame() {
        setTitle("UDP Broadcast Chat");
        setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        setMinimumSize(new Dimension(920, 560));
        setSize(1200, 760);
        setLocationRelativeTo(null);
    }

    private void installLook() {
        getContentPane().setBackground(APP_BG);
        styleField(addressField);
        styleField(portField);
        styleField(inputField);
        inputField.setText("");
        inputField.putClientProperty("JTextField.placeholderText", "Type a message and press Enter...");

        startCheck.setBackground(TOP_BG);
        startCheck.setForeground(BLUE);
        startCheck.setSelected(true);
        startCheck.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));

        messages.setEditable(false);
        messages.setFont(MONO);
        messages.setBackground(APP_BG);
        messages.setForeground(TEXT);
        messages.setCaretColor(BLUE);
        messages.setBorder(new EmptyBorder(10, 10, 10, 10));
        messages.setLineWrap(true);
        messages.setWrapStyleWord(true);

        addressList.setFont(MONO);
        addressList.setBackground(APP_BG);
        addressList.setForeground(TEXT);
        addressList.setFixedCellHeight(26);
        addressList.setBorder(BorderFactory.createMatteBorder(0, 0, 0, 1, BORDER));
        addressList.setCellRenderer(addressRenderer());

        statusLabel.setFont(LABEL);
        statusLabel.setForeground(MUTED);
        statusLabel.setHorizontalAlignment(SwingConstants.RIGHT);
    }

    private void buildLayout() {
        JPanel root = new JPanel(new BorderLayout());
        root.setBackground(APP_BG);
        setContentPane(root);

        JPanel header = new JPanel(new BorderLayout());
        header.setBackground(TOP_BG);
        header.setBorder(BorderFactory.createMatteBorder(1, 0, 1, 0, BORDER));
        root.add(header, BorderLayout.NORTH);

        JLabel title = new JLabel("(o) UDP BROADCAST");
        title.setFont(LABEL);
        title.setForeground(MUTED);
        title.setBorder(new EmptyBorder(8, 14, 7, 14));
        header.add(title, BorderLayout.NORTH);

        JPanel controls = new JPanel(new GridBagLayout());
        controls.setBackground(TOP_BG);
        controls.setBorder(new EmptyBorder(8, 14, 10, 14));
        header.add(controls, BorderLayout.CENTER);

        GridBagConstraints c = new GridBagConstraints();
        c.gridy = 0;
        c.anchor = GridBagConstraints.WEST;
        c.insets = new Insets(0, 0, 6, 14);
        controls.add(controlLabel("BROADCAST IP ADDRESS"), c);
        c.gridx = 1;
        controls.add(controlLabel("UDP PORT"), c);
        c.gridx = 2;
        controls.add(controlLabel("START"), c);

        c.gridy = 1;
        c.gridx = 0;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.weightx = 0;
        addressField.setPreferredSize(new Dimension(150, 26));
        controls.add(addressField, c);
        c.gridx = 1;
        portField.setPreferredSize(new Dimension(82, 26));
        controls.add(portField, c);
        c.gridx = 2;
        c.fill = GridBagConstraints.NONE;
        controls.add(startCheck, c);
        c.gridx = 3;
        c.weightx = 1;
        controls.add(new JLabel(), c);
        c.gridx = 4;
        c.anchor = GridBagConstraints.EAST;
        statusLabel.setText("* LISTENING");
        statusLabel.setForeground(GREEN);
        controls.add(statusLabel, c);

        JPanel center = new JPanel(new BorderLayout());
        center.setBackground(APP_BG);
        root.add(center, BorderLayout.CENTER);

        JPanel addressPanel = new JPanel(new BorderLayout());
        addressPanel.setPreferredSize(new Dimension(184, 10));
        addressPanel.setBackground(APP_BG);
        center.add(addressPanel, BorderLayout.WEST);
        addressPanel.add(sectionHeader("ADDRESSES", "+"), BorderLayout.NORTH);
        addressPanel.add(addressList, BorderLayout.CENTER);

        JPanel messagePanel = new JPanel(new BorderLayout());
        messagePanel.setBackground(APP_BG);
        center.add(messagePanel, BorderLayout.CENTER);
        messagePanel.add(sectionHeader("MESSAGES", "CLEAR"), BorderLayout.NORTH);
        messagePanel.add(scroll(messages), BorderLayout.CENTER);

        JPanel composer = new JPanel(new BorderLayout(8, 0));
        composer.setBackground(TOP_BG);
        composer.setBorder(new EmptyBorder(8, 12, 8, 12));
        root.add(composer, BorderLayout.SOUTH);
        composer.add(inputField, BorderLayout.CENTER);

        JButton sendButton = new JButton("Send");
        styleButton(sendButton);
        sendButton.addActionListener(event -> sendMessage());
        composer.add(sendButton, BorderLayout.EAST);
    }

    private void bindEvents() {
        inputField.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent event) {
                if (event.getKeyCode() == KeyEvent.VK_ENTER) {
                    sendMessage();
                }
            }
        });
        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosed(WindowEvent event) {
                udpService.stop();
            }
        });
    }

    private void loadAddresses() {
        List<BroadcastAddress> addresses = addressProvider.findBroadcastAddresses();
        addressList.setListData(addresses.toArray(BroadcastAddress[]::new));
        if (!addresses.isEmpty()) {
            addressList.setSelectedIndex(0);
            addressField.setText(addresses.getFirst().hostAddress());
        }
    }

    private void startListening() {
        if (!startCheck.isSelected()) {
            udpService.stop();
            setStatus(false);
            return;
        }

        try {
            udpService.start(Integer.parseInt(portField.getText().trim()));
            setStatus(true);
        } catch (Exception ex) {
            startCheck.setSelected(false);
            setStatus(false);
            JOptionPane.showMessageDialog(this, ex.getMessage(), "Could not start UDP listener", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void sendMessage() {
        String text = inputField.getText().trim();
        if (text.isEmpty()) {
            return;
        }

        try {
            appendMessage(new ChatMessage(LocalTime.now(), "->", addressField.getText().trim() + ":" + Integer.parseInt(portField.getText().trim()), text));
            inputField.setText("");
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, ex.getMessage(), "Could not send UDP message", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void appendMessage(ChatMessage message) {
        messages.append("%s  %s  %s  %s%n".formatted(
                timeFormat.format(message.time()),
                message.direction(),
                message.sender(),
                message.text()
        ));
        messages.setCaretPosition(messages.getDocument().getLength());
    }

    private void setStatus(boolean listening) {
        statusLabel.setText(listening ? "* LISTENING" : "* OFFLINE");
        statusLabel.setForeground(listening ? GREEN : MUTED);
    }

    private static JLabel controlLabel(String text) {
        JLabel label = new JLabel(text);
        label.setFont(LABEL);
        label.setForeground(MUTED);
        return label;
    }

    private static JPanel sectionHeader(String left, String right) {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBackground(TOP_BG);
        panel.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, BORDER));
        JLabel leftLabel = controlLabel(left);
        leftLabel.setBorder(new EmptyBorder(8, 12, 8, 12));
        panel.add(leftLabel, BorderLayout.WEST);
        JLabel rightLabel = controlLabel(right);
        rightLabel.setHorizontalAlignment(SwingConstants.RIGHT);
        rightLabel.setBorder(new EmptyBorder(8, 12, 8, 12));
        panel.add(rightLabel, BorderLayout.EAST);
        return panel;
    }

    private static JScrollPane scroll(Component component) {
        JScrollPane pane = new JScrollPane(component);
        pane.setBorder(BorderFactory.createEmptyBorder());
        pane.getViewport().setBackground(APP_BG);
        pane.setBackground(APP_BG);
        return pane;
    }

    private static void styleField(JTextField field) {
        field.setFont(MONO);
        field.setBackground(INPUT_BG);
        field.setForeground(TEXT);
        field.setCaretColor(BLUE);
        field.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(BORDER),
                new EmptyBorder(4, 9, 4, 9)
        ));
    }

    private static void styleButton(JButton button) {
        button.setFont(LABEL);
        button.setBackground(new Color(0x23477f));
        button.setForeground(TEXT);
        button.setFocusPainted(false);
        button.setBorder(new EmptyBorder(7, 13, 7, 13));
        button.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
    }

    private static ListCellRenderer<? super BroadcastAddress> addressRenderer() {
        return (list, value, index, selected, focused) -> {
            JLabel label = new JLabel((selected ? "* " : ". ") + value.hostAddress());
            label.setOpaque(true);
            label.setFont(MONO);
            label.setBackground(selected ? SELECTED : APP_BG);
            label.setForeground(selected ? BLUE : MUTED);
            label.setBorder(new EmptyBorder(0, 12, 0, 8));
            return label;
        };
    }
}
