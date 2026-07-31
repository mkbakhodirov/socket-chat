package com.example.socketchat.ui;

import com.example.socketchat.dto.Message;
import com.example.socketchat.encryption.ElGamalEncryption;
import com.example.socketchat.encryption.ElGamalEncryption.KeyPair;
import com.example.socketchat.encryption.ElGamalEncryption.PublicKey;
import com.example.socketchat.encryption.GcmEncryption;
import com.example.socketchat.model.ChatMessage;
import com.example.socketchat.model.User;
import com.example.socketchat.model.UserModel;
import com.example.socketchat.service.UdpBroadcastService;
import com.google.inject.Inject;
import com.google.inject.Singleton;

import javax.swing.*;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.Enumeration;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

@Singleton
public class Controller {

    UdpBroadcastService udpService;
    @Inject
    ElGamalEncryption elGamalEncryption;
    @Inject
    GcmEncryption gcmEncryption;
    KeyPair identity;

    private final MainFrame frame = new MainFrame();
    private final DateTimeFormatter timeFormat = DateTimeFormatter.ofPattern("HH:mm:ss.SSS");

    ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);

    public void run() {
        frame.hexKeyField.setText("");
        frame.receiveHexKeyField.setText("");

        identity = elGamalEncryption.generateKeyPair();

        loadAddresses();

        startListening();

        frame.startCheck.addActionListener(event -> {
            if (frame.startCheck.isSelected()) {
                startListening();
            } else {
                stopListening();
            }
        });

        frame.encryptionCheck.addActionListener(event -> selectEncryption());

        frame.elGamalCheck.addActionListener(event -> selectElGamal());

        frame.viewElGamalButton.addActionListener(event -> showElGamalForm());

        frame.addressList.addListSelectionListener(event -> {
            if (!event.getValueIsAdjusting() && frame.elGamalCheck.isSelected()) {
                showKeyForSelectedUser();
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

    private void selectEncryption() {
        boolean enabled = frame.encryptionCheck.isSelected();
        if (enabled) {
            String key = gcmEncryption.generateKey();
            frame.hexKeyField.setText(key);
            frame.receiveHexKeyField.setText(key);
        } else {
            frame.elGamalCheck.setSelected(false);
            frame.hexKeyField.setText("");
            frame.receiveHexKeyField.setText("");
        }

        frame.hexKeyField.setEditable(enabled && !frame.elGamalCheck.isSelected());
        frame.receiveHexKeyField.setEditable(enabled && !frame.elGamalCheck.isSelected());
    }

    private void selectElGamal() {
        if (frame.elGamalCheck.isSelected()) {
            if (!frame.encryptionCheck.isSelected()) {
                frame.encryptionCheck.setSelected(true);
            }
            frame.hexKeyField.setEditable(false);
            frame.receiveHexKeyField.setEditable(false);
            showKeyForSelectedUser();
        } else {
            selectEncryption();
        }
    }

    private void showKeyForSelectedUser() {
        User user = (User) frame.addressList.getSelectedValue();
        if (user == null) {
            JOptionPane.showMessageDialog(
                    frame,
                    "Select a user to derive an AES key",
                    "Warning",
                    JOptionPane.ERROR_MESSAGE
            );
            frame.elGamalCheck.setSelected(false);
            frame.encryptionCheck.setSelected(true);
            selectEncryption();
            return;
        }

        frame.hexKeyField.setText(elGamalEncryption.toEncryptionKey(user.getPublicKey(), identity.k()));
        frame.receiveHexKeyField.setText(
                elGamalEncryption.toDecryptionKey(user.getPublicKey(), identity.x(), identity.p(), identity.g()
        ));
    }

    private void showElGamalForm() {
        frame.elGamalGField.setText(identity.g().toString());
        frame.elGamalPField.setText(identity.p().toString());
        frame.elGamalXField.setText(identity.x().toString());
        frame.elGamalKField.setText(identity.k().toString());
        frame.elGamalYField.setText(identity.y().toString());
        frame.elGamalEphemeralField.setText(identity.ephemeral().toString());

        User user = (User) frame.addressList.getSelectedValue();
        if (user != null) {
            frame.selectedUserGField.setText(user.getPublicKey().g().toString());
            frame.selectedUserPField.setText(user.getPublicKey().p().toString());
            frame.selectedUserYField.setText(user.getPublicKey().y().toString());
            frame.selectedUserEphemeralField.setText(user.getPublicKey().ephemeral().toString());
        } else {
            frame.selectedUserGField.setText("");
            frame.selectedUserPField.setText("");
            frame.selectedUserYField.setText("");
            frame.selectedUserEphemeralField.setText("");
        }

        Runnable calculate = () -> {
            try {
                BigInteger p = parsePositive(frame.elGamalPField, "P");
                KeyPair keyPair = elGamalEncryption.calculate(
                        parsePositive(frame.elGamalGField, "G"),
                        p,
                        parsePositive(frame.elGamalXField, "x"),
                        parsePositive(frame.elGamalKField, "k")
                );
                frame.elGamalYField.setText(keyPair.y().toString());
                frame.elGamalEphemeralField.setText(keyPair.ephemeral().toString());
            } catch (RuntimeException ex) {
                JOptionPane.showMessageDialog(frame, ex.getMessage(), "Invalid ElGamal values", JOptionPane.ERROR_MESSAGE);
            }
        };

        frame.elGamalRandomButton.addActionListener(event -> {
            try {
                BigInteger p = parsePositive(frame.elGamalPField, "P");
                frame.elGamalXField.setText(elGamalEncryption.randomExponent(p).toString());
                frame.elGamalKField.setText(elGamalEncryption.randomExponent(p).toString());
                calculate.run();
            } catch (RuntimeException ex) {
                JOptionPane.showMessageDialog(frame, ex.getMessage(), "Invalid ElGamal values", JOptionPane.ERROR_MESSAGE);
            }
        });

        frame.elGamalCalculateButton.addActionListener(event -> calculate.run());

        int result = JOptionPane.showConfirmDialog(
                frame,
                frame.elGamalContentPanel,
                "El Gamal Key Exchange",
                JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.PLAIN_MESSAGE
        );
        if (result != JOptionPane.OK_OPTION) {
            return;
        }

        try {
            identity = elGamalEncryption.calculate(
                    parsePositive(frame.elGamalGField, "G"),
                    parsePositive(frame.elGamalPField, "P"),
                    parsePositive(frame.elGamalXField, "x"),
                    parsePositive(frame.elGamalKField, "k")
            );

            if (frame.startCheck.isSelected()) {
                startListening();
            }

            if (frame.elGamalCheck.isSelected()) {
                showKeyForSelectedUser();
            }
        } catch (RuntimeException ex) {
            JOptionPane.showMessageDialog(frame, ex.getMessage(), "Could not apply ElGamal values", JOptionPane.ERROR_MESSAGE);
        }
    }

    private BigInteger parsePositive(JTextField field, String name) {
        try {
            return new BigInteger(field.getText().trim());
        } catch (NumberFormatException ex) {
            throw new IllegalArgumentException(name + " must be a decimal integer");
        }
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
                    elGamalEncryption.encodePublicKey(identity.publicKey()),
                    this::appendMessage,
                    new Consumer<Throwable>() {
                        @Override
                        public void accept(Throwable t) {
                            t.printStackTrace();
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
            if (!frame.encryptionCheck.isSelected()) {
                udpService.sendPlain(text, isa);
            } else if (!frame.elGamalCheck.isSelected()) {
                udpService.sendEncrypted(text, frame.hexKeyField.getText().trim(), false, isa);
            } else {
                udpService.sendEncrypted(text, frame.hexKeyField.getText().trim(), true, isa);
            }
            frame.inputField.setText("");
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(frame, ex.getMessage(), "Could not send UDP message", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void appendMessage(Message message) {
        switch (message.getType()) {
            case UdpBroadcastService.HELLO: {
                SwingUtilities.invokeLater(() -> {
                    PublicKey publicKey;
                    try {
                        publicKey = elGamalEncryption.decodePublicKey(message.getPayload());
                    } catch (Exception ex) {
                        ex.printStackTrace();
                        frame.messages.append("Ignored invalid public key from " + message.getAddress() + "\n");
                        return;
                    }

                    User user = new User(LocalTime.now(), message.getAddress(), publicKey);
                    UserModel um = (UserModel) frame.addressList.getModel();
                    Enumeration<User> en = um.elements();
                    while (en.hasMoreElements()) {
                        User u = en.nextElement();
                        if (u.getAddress().equals(user.getAddress())) {
                            u.setTime(user.getTime());
                            u.setPublicKey(user.getPublicKey());
                            if (frame.elGamalCheck.isSelected()
                                    && frame.addressList.getSelectedValue() == u) {
                                showKeyForSelectedUser();
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

            case UdpBroadcastService.ENCRYPTED_MESSAGE, UdpBroadcastService.ELGAMAL_ENCRYPTED_MESSAGE: {
                String text;
                try {
                    text = gcmEncryption.decrypt(
                            message.getPayload(), frame.receiveHexKeyField.getText().trim()
                    );
                } catch (Exception ex) {
                    SwingUtilities.invokeLater(() -> {
                        frame.messages.append("Error decrypting message: " + ex.getMessage() + "\n");
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

//
//    private void appendMessage(Message message) {
//        switch (message.getType()) {
//            case UdpBroadcastService.HELLO -> receiveHello(message);
//            case UdpBroadcastService.PLAIN_MESSAGE ->
//                    displayMessage(message, new String(message.getPayload(),
//                            StandardCharsets.UTF_8));
//            case UdpBroadcastService.ENCRYPTED_MESSAGE ->
//                    decryptWithManualKey(message);
//            case UdpBroadcastService.ELGAMAL_ENCRYPTED_MESSAGE ->
//                    decryptWithElGamal(message);
//            default -> frame.messages.append(
//                    "Ignored unknown message type\n");
//        }
//    }
//
//    private void receiveHello(Message message) {
//        final PublicKey publicKey;
//        try {
//            publicKey = elGamalEncryption.decodePublicKey(
//                    message.getPayload());
//        } catch (RuntimeException ex) {
//            frame.messages.append("Ignored invalid ElGamal data from "
//                    + message.getAddress() + "\n");
//            return;
//        }
//
//        UserModel model = (UserModel) frame.addressList.getModel();
//        User existing = findUser(message.getAddress());
//        if (existing == null) {
//            model.addElement(new User(LocalTime.now(),
//                    message.getAddress(), publicKey));
//        } else {
//            existing.setTime(LocalTime.now());
//            existing.setPublicKey(publicKey);
//        }
//        if (frame.elGamalCheck.isSelected()) {
//            showDerivedKeyForSelectedUser();
//        }
//    }
//
//    private void decryptWithManualKey(Message message) {
//        try {
//            String key = frame.elGamalCheck.isSelected()
//                    ? manualHexKey : frame.hexKeyField.getText().trim();
//            displayMessage(message,
//                    gcmEncryption.decrypt(message.getPayload(), key));
//        } catch (Exception ex) {
//            showReceiveError(ex);
//        }
//    }
//
//    private void decryptWithElGamal(Message message) {
//        User sender = findUser(message.getAddress());
//        if (sender == null) {
//            showReceiveError(new IllegalStateException(
//                    "No ElGamal identity is known for "
//                            + message.getAddress()));
//            return;
//        }
//        try {
//            String key = elGamalEncryption.toDecryptionKey(
//                    sender.getPublicKey(), identity.x(),
//                    identity.p(), identity.g());
//            displayMessage(message,
//                    gcmEncryption.decrypt(message.getPayload(), key));
//        } catch (Exception ex) {
//            showReceiveError(ex);
//        }
//    }
//
//    private User findUser(String address) {
//        Enumeration<User> users =
//                ((UserModel) frame.addressList.getModel()).elements();
//        while (users.hasMoreElements()) {
//            User user = users.nextElement();
//            if (user.getAddress().equals(address)) {
//                return user;
//            }
//        }
//        return null;
//    }
//
//    private void displayMessage(Message message, String text) {
//        ChatMessage chatMessage = new ChatMessage(LocalTime.now(),
//                "<-", message.getAddress(), text);
//        frame.messages.append("%s  %s  %s  %s%n".formatted(
//                timeFormat.format(chatMessage.time()),
//                chatMessage.direction(),
//                chatMessage.sender(),
//                chatMessage.text()));
//        frame.messages.setCaretPosition(
//                frame.messages.getDocument().getLength());
//    }
//
//    private void showReceiveError(Throwable throwable) {
//        frame.messages.append("Error decrypting message: "
//                + throwable.getMessage() + "\n");
//    }
}
