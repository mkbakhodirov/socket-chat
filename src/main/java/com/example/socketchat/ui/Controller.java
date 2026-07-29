package com.example.socketchat.ui;

import com.example.socketchat.dto.Message;
import com.example.socketchat.encryption.ElGamalEncryption;
import com.example.socketchat.model.ChatMessage;
import com.example.socketchat.model.User;
import com.example.socketchat.model.UserModel;
import com.example.socketchat.service.UdpBroadcastService;
import com.google.inject.Inject;
import com.google.inject.Singleton;

import javax.swing.*;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.Enumeration;
import java.util.HexFormat;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

@Singleton
public class Controller {

    UdpBroadcastService udpService;
    @Inject
    ElGamalEncryption elGamalEncryption;
    private KeyPair identity;

    private final MainFrame frame = new MainFrame();
    private final DateTimeFormatter timeFormat = DateTimeFormatter.ofPattern("HH:mm:ss.SSS");

    ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);

    public void run() {
        try {
            identity = elGamalEncryption.generateKeyPair();
            frame.publicKeyField.setText(HexFormat.of().formatHex(elGamalEncryption.encodePublicKey(identity.getPublic())));
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(frame, ex.getMessage(),
                    "Could not create encryption identity", JOptionPane.ERROR_MESSAGE);
            return;
        }

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

        frame.setLocationRelativeTo(null);
        frame.setVisible(true);
    }

    private void loadAddresses() {

        scheduler.scheduleAtFixedRate(() -> {
            // Безопасно переносим выполнение в поток обработки событий Swing (EDT)
            SwingUtilities.invokeLater(() -> {
                LocalTime now = LocalTime.now();
                LocalTime cutoffTime = now.minusMinutes(1); // Время отсечки (1 минута назад)

                UserModel model = (UserModel) frame.addressList.getModel();

                // Итерируемся с конца списка к началу
                for (int i = model.getSize() - 1; i >= 0; i--) {
                    User user = model.getElementAt(i);

                    // ПРАВИЛЬНОЕ УСЛОВИЕ:
                    // Если время пользователя МЕНЬШЕ (раньше), чем текущее время минус 1 минута,
                    // значит, пользователь окончательно устарел, и мы его удаляем.
                    if (user.getTime().isBefore(cutoffTime)) {
                        model.remove(i);
                    }
                }
            });
        }, 45, 45, TimeUnit.SECONDS);
    }

    private void startListening() {
        if (!frame.startCheck.isSelected()) {
            udpService.stop();
            setStatus(false);
            return;
        }

        try {
            InetSocketAddress broadcastAddr = new InetSocketAddress(frame.addressField.getText(), Integer.parseInt(frame.portField.getText()));
            udpService = new UdpBroadcastService(
                    broadcastAddr,
                    elGamalEncryption.encodePublicKey(identity.getPublic()),
                    this::appendMessage,
                    new Consumer<Throwable>() {
                        @Override
                        public void accept(Throwable t) {
                            SwingUtilities.invokeLater(() -> {
                                frame.messages.append("Error: " + t.getMessage() + "\n");
                            });
                        }
                    }
            );
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
        User user = (User) frame.addressList.getSelectedValue();
        if (user == null) {
            return;
        }
        try {
            InetSocketAddress isa = new InetSocketAddress(user.getAddress(), Integer.parseInt(frame.portField.getText().trim()));
//            udpService.sendPlain(text, isa);
            udpService.sendEncrypted(text, elGamalEncryption.decodePublicKey(user.getPublicKey()), isa);
            frame.inputField.setText("");
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(frame, ex.getMessage(), "Could not send UDP message", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void appendMessage(Message message) {
        switch (message.getType()) {
            case UdpBroadcastService.HELLO: {
                SwingUtilities.invokeLater(() -> {
                    try {
                        elGamalEncryption.decodePublicKey(message.getPayload());
                    } catch (Exception ex) {
                        frame.messages.append("Ignored invalid public key from "
                                + message.getAddress() + "\n");
                        return;
                    }

                    User user = new User(LocalTime.now(), message.getAddress(), message.getPayload());
                    UserModel um = (UserModel) frame.addressList.getModel();
                    Enumeration<User> en = um.elements();
                    while (en.hasMoreElements()) {
                        User u = en.nextElement();
                        if (u.getAddress().equals(user.getAddress())) {
                            u.setTime(user.getTime());
                            if (!u.hasPublicKey(user.getPublicKey())) {
                                u.setPublicKey(user.getPublicKey());
                            }
                            return;
                        }
                    }
                    um.addElement(user);
                });
                break;
            }

            case UdpBroadcastService.PLAIN_MESSAGE: {
                ChatMessage cm = new ChatMessage(
                        LocalTime.now(),
                        "<-",
                        message.getAddress(),
                        new String(message.getPayload(), StandardCharsets.UTF_8)
                );
                frame.messages.append("%s  %s  %s  %s%n".formatted(
                        timeFormat.format(cm.time()),
                        cm.direction(),
                        cm.sender(),
                        cm.text()
                ));
                frame.messages.setCaretPosition(frame.messages.getDocument().getLength());
                break;
            }

            case UdpBroadcastService.ENCRYPTED_MESSAGE: {
                String text;
                try {
                    text = elGamalEncryption.decrypt(message.getPayload(), identity.getPrivate());
                } catch (Throwable t) {
                    SwingUtilities.invokeLater(() -> {
                        frame.messages.append("Error: " + t.getMessage() + "\n");
                    });
                    return;
                }

                ChatMessage cm = new ChatMessage(LocalTime.now(), "<-", message.getAddress(), text);
                frame.messages.append("%s  %s  %s  %s%n".formatted(
                        timeFormat.format(cm.time()),
                        cm.direction(),
                        cm.sender(),
                        cm.text()
                ));
                frame.messages.setCaretPosition(frame.messages.getDocument().getLength());
                break;
            }
        }
    }
}
