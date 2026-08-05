package com.example.socketchat.ui;

import com.example.socketchat.dto.Message;
import com.example.socketchat.encryption.CbcEncryption;
import com.example.socketchat.encryption.DiffieHellmanEncryption;
import com.example.socketchat.encryption.DsaSigning;
import com.example.socketchat.model.ChatMessage;
import com.example.socketchat.model.User;
import com.example.socketchat.model.UserModel;
import com.example.socketchat.service.UdpBroadcastService;
import com.google.inject.Inject;
import com.google.inject.Singleton;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
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
    DiffieHellmanEncryption diffieHellmanEncryption;
    @Inject
    CbcEncryption cbcEncryption;
    @Inject
    DsaSigning dsaSigning;
    DiffieHellmanEncryption.KeyPair diffieHellmanIdentity;
    DsaSigning.KeyPair dsaIdentity;
    private boolean diffieHellmanFormInitialized;
    private boolean diffieHellmanActionsInitialized;
    private boolean dsaFormInitialized;
    private boolean dsaActionsInitialized;

    private final MainFrame frame = new MainFrame();
    private final DateTimeFormatter timeFormat = DateTimeFormatter.ofPattern("HH:mm:ss.SSS");

    ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);

    public void run() {
        frame.hexKeyField.setText("");

        diffieHellmanIdentity = diffieHellmanEncryption.generateKeyPair();
        dsaIdentity = dsaSigning.generateKeyPair();

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

        frame.diffieHellmanCheck.addActionListener(event -> selectDiffieHellman());

        frame.viewDiffieHellmanButton.addActionListener(event -> showDiffieHellmanForm());

        frame.diffieHellmanRandomButton.addActionListener(event -> randomDiffieHellman());

        frame.diffieHellmanCalculateButton.addActionListener(event -> calculateDiffieHellman());

        frame.diffieHellmanCopyButton.addActionListener(event -> copyDiffieHellman());

        frame.viewDsaButton.addActionListener(event -> showDsaForm());

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
            if (frame.hexKeyField.getText().isBlank()) {
                String k = frame.diffieHellmanKField.getText().trim();
                String key = k.isEmpty()
                        ? cbcEncryption.generateKey()
                        : diffieHellmanEncryption.toSecretKey(new BigInteger(k));
                frame.hexKeyField.setText(key);
            }
        } else {
            frame.diffieHellmanCheck.setSelected(false);
        }
    }

    private void selectDiffieHellman() {
        if (frame.diffieHellmanCheck.isSelected()) {
            if (!frame.encryptionCheck.isSelected()) {
                frame.encryptionCheck.setSelected(true);
            }
            if (frame.diffieHellmanKField.getText().isBlank()) {
                frame.hexKeyField.setText("");
            }
        } else {
            selectEncryption();
        }
    }

    private void showDiffieHellmanForm() {
        if (!diffieHellmanFormInitialized) {
            frame.diffieHellmanGField.setText(diffieHellmanIdentity.g().toString());
            frame.diffieHellmanPField.setText(diffieHellmanIdentity.p().toString());
            frame.diffieHellmanXField.setText(diffieHellmanIdentity.x().toString());
            frame.diffieHellmanYField.setText(diffieHellmanIdentity.y().toString());
            diffieHellmanFormInitialized = true;
        }

        int result = JOptionPane.showConfirmDialog(
                frame,
                frame.diffieHellmanContentPanel,
                "Diffie-Hellman Key Exchange",
                JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.PLAIN_MESSAGE
        );
        if (result != JOptionPane.OK_OPTION) {
            return;
        }

        calculateDiffieHellman();
    }

    private void randomDiffieHellman() {
        try {
            BigInteger p = parsePositive(frame.diffieHellmanPField, "P");
            frame.diffieHellmanXField.setText(diffieHellmanEncryption.randomExponent(p).toString());
            calculateDiffieHellman();
        } catch (RuntimeException ex) {
            JOptionPane.showMessageDialog(frame, ex.getMessage(), "Invalid Diffie-Hellman values", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void calculateDiffieHellman() {
        try {
            diffieHellmanIdentity = diffieHellmanEncryption.calculate(
                    parsePositive(frame.diffieHellmanGField, "G"),
                    parsePositive(frame.diffieHellmanPField, "P"),
                    parsePositive(frame.diffieHellmanXField, "x")
            );
            frame.diffieHellmanYField.setText(diffieHellmanIdentity.y().toString());
            if (!frame.selectedUserDiffieHellmanYField.getText().isBlank()) {
                DiffieHellmanEncryption.PublicKey publicKey = new DiffieHellmanEncryption.PublicKey(
                        diffieHellmanIdentity.g(), diffieHellmanIdentity.p(),
                        parsePositive(frame.selectedUserDiffieHellmanYField, "Selected user's y")
                );
                frame.diffieHellmanKField.setText(diffieHellmanEncryption.toSecretKey(
                        publicKey, diffieHellmanIdentity.x(), diffieHellmanIdentity.p(), diffieHellmanIdentity.g()
                ));
                frame.hexKeyField.setText(frame.diffieHellmanKField.getText());
            } else {
                frame.diffieHellmanKField.setText("");
                frame.hexKeyField.setText("");
            }
        } catch (RuntimeException ex) {
            JOptionPane.showMessageDialog(frame, ex.getMessage(), "Invalid Diffie-Hellman values", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void copyDiffieHellman() {
        String publicValues = "G=" + frame.diffieHellmanGField.getText().trim()
                + ", P=" + frame.diffieHellmanPField.getText().trim()
                + ", y=" + frame.diffieHellmanYField.getText().trim();
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(publicValues), null);
    }

    private BigInteger parsePositive(JTextField field, String name) {
        try {
            return new BigInteger(field.getText().trim());
        } catch (NumberFormatException ex) {
            throw new IllegalArgumentException(name + " must be a decimal integer");
        }
    }

    private void showDsaForm() {
        if (!dsaFormInitialized) {
            frame.dsaPField.setText(dsaIdentity.p().toString());
            frame.dsaQField.setText(dsaIdentity.q().toString());
            frame.dsaGField.setText(dsaIdentity.g().toString());
            frame.dsaXField.setText(dsaIdentity.x().toString());
            frame.dsaYField.setText(dsaIdentity.y().toString());
            dsaFormInitialized = true;
        }

        Runnable calculate = () -> {
            try {
                DsaSigning.KeyPair keyPair = dsaSigning.calculate(
                        parsePositive(frame.dsaPField, "P"),
                        parsePositive(frame.dsaQField, "Q"),
                        parsePositive(frame.dsaGField, "G"),
                        parsePositive(frame.dsaXField, "x")
                );
                frame.dsaYField.setText(keyPair.y().toString());
            } catch (RuntimeException ex) {
                JOptionPane.showMessageDialog(frame, ex.getMessage(), "Invalid DSA values", JOptionPane.ERROR_MESSAGE);
            }
        };

        if (!dsaActionsInitialized) {
            frame.dsaRandomButton.addActionListener(event -> {
                try {
                    BigInteger q = parsePositive(frame.dsaQField, "Q");
                    frame.dsaXField.setText(dsaSigning.randomValue(q).toString());
                    calculate.run();
                } catch (RuntimeException ex) {
                    JOptionPane.showMessageDialog(frame, ex.getMessage(), "Invalid DSA values", JOptionPane.ERROR_MESSAGE);
                }
            });

            frame.dsaCalculateButton.addActionListener(event -> calculate.run());

            frame.dsaCopyButton.addActionListener(event -> {
                calculate.run();
                String publicValues = "P=" + frame.dsaPField.getText().trim()
                        + ", Q=" + frame.dsaQField.getText().trim()
                        + ", G=" + frame.dsaGField.getText().trim()
                        + ", y=" + frame.dsaYField.getText().trim();
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(publicValues), null);
            });
            dsaActionsInitialized = true;
        }

        int result = JOptionPane.showConfirmDialog(
                frame,
                frame.dsaContentPanel,
                "DSA Signature",
                JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.PLAIN_MESSAGE
        );
        if (result != JOptionPane.OK_OPTION) {
            return;
        }

        try {
            dsaIdentity = dsaSigning.calculate(
                    parsePositive(frame.dsaPField, "P"),
                    parsePositive(frame.dsaQField, "Q"),
                    parsePositive(frame.dsaGField, "G"),
                    parsePositive(frame.dsaXField, "x")
            );
            if (!frame.selectedUserDsaYField.getText().isBlank()) {
                dsaSigning.publicKey(
                        dsaIdentity.p(), dsaIdentity.q(), dsaIdentity.g(),
                        parsePositive(frame.selectedUserDsaYField, "Selected user's y")
                );
            }
        } catch (RuntimeException ex) {
            JOptionPane.showMessageDialog(frame, ex.getMessage(), "Could not apply DSA values", JOptionPane.ERROR_MESSAGE);
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
            if (udpService != null) {
                udpService.stop();
                udpService = null;
            }
            setStatus(false);
            return;
        }

        try {
            InetSocketAddress broadcastAddr = new InetSocketAddress(frame.addressField.getText(), Integer.parseInt(frame.portField.getText()));
            if (udpService != null) {
                udpService.stop();
            }
            udpService = new UdpBroadcastService(
                    broadcastAddr,
                    this::appendMessage,
                    new Consumer<Throwable>() {
                        @Override
                        public void accept(Throwable t) {
                            t.printStackTrace();
                            SwingUtilities.invokeLater(() -> frame.messages.append("Error: " + t.getMessage() + "\n"));
                        }
                    }
            );
            udpService.start(Integer.parseInt(frame.portField.getText().trim()));
            udpService.execute();
            setStatus(true);
        } catch (Exception ex) {
            ex.printStackTrace();
            if (udpService != null) {
                udpService.stop();
            }
            udpService = null;
            frame.startCheck.setSelected(false);
            setStatus(false);
            JOptionPane.showMessageDialog(frame, ex.getMessage(), "Could not start UDP listener", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void stopListening() {
        if (udpService != null) {
            udpService.stop();
            udpService = null;
        }
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
            if (frame.signatureCheck.isSelected()) {
                if (frame.encryptionCheck.isSelected()) {
                    byte[] message = cbcEncryption.encrypt(text, frame.hexKeyField.getText().trim());
                    byte[] payload = dsaSigning.encodeSigned(message, dsaSigning.sign(message, dsaIdentity));
                    udpService.send(UdpBroadcastService.SIGNED_ENCRYPTED_MESSAGE, payload, isa);
                } else {
                    byte[] message = text.getBytes(StandardCharsets.UTF_8);
                    byte[] payload = dsaSigning.encodeSigned(message, dsaSigning.sign(message, dsaIdentity));
                    udpService.send(UdpBroadcastService.SIGNED_PLAIN_MESSAGE, payload, isa);
                }
            } else if (frame.encryptionCheck.isSelected()) {
                byte[] payload = cbcEncryption.encrypt(text, frame.hexKeyField.getText().trim());
                udpService.send(UdpBroadcastService.ENCRYPTED_MESSAGE, payload, isa);
            } else {
                byte[] payload = text.getBytes(StandardCharsets.UTF_8);
                udpService.send(UdpBroadcastService.PLAIN_MESSAGE, payload, isa);
            }
            frame.inputField.setText("");
        } catch (Exception ex) {
            ex.printStackTrace();
            JOptionPane.showMessageDialog(frame, ex.getMessage(), "Could not send UDP message", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void appendMessage(Message message) {
        switch (message.getType()) {
            case UdpBroadcastService.HELLO: {
                SwingUtilities.invokeLater(() -> {
                    User user = new User(LocalTime.now(), message.getAddress());
                    UserModel um = (UserModel) frame.addressList.getModel();
                    Enumeration<User> en = um.elements();
                    while (en.hasMoreElements()) {
                        User u = en.nextElement();
                        if (u.getAddress().equals(user.getAddress())) {
                            u.setTime(user.getTime());
                            return;
                        }
                    }
                    um.addElement(user);
                });
                break;
            }

            case UdpBroadcastService.PLAIN_MESSAGE: {
                String text = new String(message.getPayload(), StandardCharsets.UTF_8);
                ChatMessage cm = new ChatMessage(LocalTime.now(), "<-", message.getAddress(), text);
                appendMessage(cm);
                break;
            }

            case UdpBroadcastService.ENCRYPTED_MESSAGE: {
                String text;
                try {
                    text = cbcEncryption.decrypt(message.getPayload(), frame.hexKeyField.getText().trim());
                } catch (Exception ex) {
                    ex.printStackTrace();
                    SwingUtilities.invokeLater(() -> frame.messages.append("Error decrypting message: " + ex.getMessage() + "\n"));
                    return;
                }

                ChatMessage cm = new ChatMessage(LocalTime.now(), "<-", message.getAddress(), text);
                appendMessage(cm);
                break;
            }

            case UdpBroadcastService.SIGNED_PLAIN_MESSAGE: {
                appendSignedMessage(message, false);
                break;
            }

            case UdpBroadcastService.SIGNED_ENCRYPTED_MESSAGE: {
                appendSignedMessage(message, true);
                break;
            }
        }
    }

    private void appendMessage(ChatMessage cm) {
        frame.messages.append("%s  %s  %s  %s%n".formatted(
                timeFormat.format(cm.time()),
                cm.direction(),
                cm.sender(),
                cm.text()
        ));
        frame.messages.setCaretPosition(frame.messages.getDocument().getLength());
    }

    private void appendSignedMessage(Message message, boolean encrypted) {
        try {
            if (frame.selectedUserDsaYField.getText().isBlank()) {
                throw new IllegalArgumentException("Missing selected user's DSA public value");
            }
            DsaSigning.PublicKey publicKey = dsaSigning.publicKey(
                    dsaIdentity.p(), dsaIdentity.q(), dsaIdentity.g(),
                    parsePositive(frame.selectedUserDsaYField, "Selected user's y")
            );
            DsaSigning.SignedMessage signedMessage = dsaSigning.decodeSigned(message.getPayload());
            if (!dsaSigning.verify(signedMessage.message(), signedMessage.signature(), publicKey)) {
                throw new IllegalArgumentException("Invalid DSA signature");
            }
            String text = encrypted
                    ? cbcEncryption.decrypt(signedMessage.message(), frame.hexKeyField.getText().trim())
                    : new String(signedMessage.message(), StandardCharsets.UTF_8);

            ChatMessage cm = new ChatMessage(LocalTime.now(), "<-", message.getAddress(), text);
            appendMessage(cm);
        } catch (Exception ex) {
            ex.printStackTrace();
            frame.messages.append("Error verifying signed message: " + ex.getMessage() + "\n");
        }
    }
}
