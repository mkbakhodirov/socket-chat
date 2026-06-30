package com.example.socketchat.ui;

import com.example.socketchat.model.BroadcastAddress;
import com.example.socketchat.model.ChatMessage;
import com.example.socketchat.service.BroadcastAddressProvider;
import com.example.socketchat.service.UdpBroadcastService;
import com.google.inject.Inject;

import javax.swing.*;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

public class Controller {

    @Inject
    private BroadcastAddressProvider addressProvider;
    @Inject
    private UdpBroadcastService udpService;

    private final MainFrame frame = new MainFrame();
    private final DateTimeFormatter timeFormat = DateTimeFormatter.ofPattern("HH:mm:ss.SSS");

    public void run() {
        loadAddresses();

        startListening();

        frame.startCheck.addActionListener(event -> setStatus(frame.startCheck.isSelected()));

        frame.inputField.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent event) {
                if (event.getKeyCode() == KeyEvent.VK_ENTER) {
                    sendMessage();
                }
            }
        });

        frame.sendButton.addActionListener(event -> sendMessage());

        frame.setVisible(true);
    }

    private void loadAddresses() {
        List<BroadcastAddress> addresses = addressProvider.findBroadcastAddresses();
        List<String> hostAddresses = addresses.stream().map(BroadcastAddress::hostAddress).toList();
        frame.addressList.setListData(hostAddresses.toArray(String[]::new));
        if (!addresses.isEmpty()) {
            frame.addressList.setSelectedIndex(0);
            frame.addressField.setText(addresses.getFirst().hostAddress());
        }
    }

    private void startListening() {
        if (!frame.startCheck.isSelected()) {
            udpService.stop();
            setStatus(false);
            return;
        }

        try {
            udpService.start(Integer.parseInt(frame.portField.getText().trim()));
            setStatus(true);
        } catch (Exception ex) {
            frame.startCheck.setSelected(false);
            setStatus(false);
            JOptionPane.showMessageDialog(frame, ex.getMessage(), "Could not start UDP listener", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void setStatus(boolean listening) {
        frame.statusLabel.setText(listening ? "* LISTENING" : "* OFFLINE");
    }

    private void sendMessage() {
        String text = frame.inputField.getText().trim();
        if (text.isEmpty()) {
            return;
        }

        try {
            appendMessage(new ChatMessage(LocalTime.now(), "->", frame.addressField.getText().trim() + ":" + Integer.parseInt(frame.portField.getText().trim()), text));
            frame.inputField.setText("");
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(frame, ex.getMessage(), "Could not send UDP message", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void appendMessage(ChatMessage message) {
        frame.messages.append("%s  %s  %s  %s%n".formatted(
                timeFormat.format(message.time()),
                message.direction(),
                message.sender(),
                message.text()
        ));
        frame.messages.setCaretPosition(frame.messages.getDocument().getLength());
    }
}
