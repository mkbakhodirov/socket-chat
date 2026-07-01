package com.example.socketchat.ui;

import com.example.socketchat.model.BroadcastAddress;
import com.example.socketchat.model.ChatMessage;
import com.example.socketchat.service.BroadcastAddressProvider;
import com.example.socketchat.service.UdpBroadcastService;
import com.google.inject.Inject;

import javax.swing.*;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.net.InetSocketAddress;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.function.Consumer;

public class Controller {

    @Inject
    private BroadcastAddressProvider addressProvider;

    UdpBroadcastService udpService;

    private final MainFrame frame = new MainFrame();
    private final DateTimeFormatter timeFormat = DateTimeFormatter.ofPattern("HH:mm:ss.SSS");

    public void run() {
        loadAddresses();

        startListening();

        frame.startCheck.addActionListener(event -> {
            if (frame.startCheck.isSelected()) {
                startListening();
            } else {
                stopListening();
            }
        });

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
        String[] localAddresses = addresses.stream().map(BroadcastAddress::localAddress).toArray(String[]::new);
        frame.addressList.setListData(localAddresses);
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
            InetSocketAddress broadcastAddr = new InetSocketAddress(frame.addressField.getText(), Integer.parseInt(frame.portField.getText()));
            udpService = new UdpBroadcastService(broadcastAddr, this::appendMessage, new Consumer<Throwable>() {
                @Override
                public void accept(Throwable t) {
                    SwingUtilities.invokeLater(() -> {
                        frame.messages.append("Error: " + t.getMessage() + "\n");
                    });
                }
            });
            udpService.start(Integer.parseInt(frame.portField.getText().trim()));
            udpService.execute();
            setStatus(true);
        } catch (Exception ex) {
            frame.startCheck.setSelected(false);
            setStatus(false);
            JOptionPane.showMessageDialog(frame, ex.getMessage(), "Could not start UDP listener", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void stopListening() {
        udpService.stop();
        setStatus(false);
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
            udpService.send(new ChatMessage(LocalTime.now(), "->", frame.addressField.getText().trim() + ":" + Integer.parseInt(frame.portField.getText().trim()), text));
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
