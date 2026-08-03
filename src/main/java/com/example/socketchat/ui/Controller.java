package com.example.socketchat.ui;

import com.example.socketchat.dto.Message;
import com.example.socketchat.encryption.DiffieHellmanEncryption;
import com.example.socketchat.encryption.GcmEncryption;
import com.example.socketchat.model.ChatMessage;
import com.example.socketchat.model.User;
import com.example.socketchat.model.UserModel;
import com.example.socketchat.service.UdpBroadcastService;
import com.google.inject.Inject;
import com.google.inject.Singleton;

import javax.swing.*;
import java.awt.Toolkit;
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
    GcmEncryption gcmEncryption;
    DiffieHellmanEncryption.KeyPair diffieHellmanIdentity;

    private final MainFrame frame = new MainFrame();
    private final DateTimeFormatter timeFormat = DateTimeFormatter.ofPattern("HH:mm:ss.SSS");

    ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);

    public void run() {
        frame.hexKeyField.setText("");

        diffieHellmanIdentity = diffieHellmanEncryption.generateKeyPair();

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
        } else {
            frame.diffieHellmanCheck.setSelected(false);
            frame.hexKeyField.setText("");
        }

        frame.hexKeyField.setEditable(enabled && !frame.diffieHellmanCheck.isSelected());
    }

    private void selectDiffieHellman() {
        if (frame.diffieHellmanCheck.isSelected()) {
            if (!frame.encryptionCheck.isSelected()) {
                frame.encryptionCheck.setSelected(true);
            }
            frame.hexKeyField.setEditable(false);
        } else {
            selectEncryption();
        }
    }

    private void showDiffieHellmanForm() {
        frame.diffieHellmanGField.setText(diffieHellmanIdentity.g().toString());
        frame.diffieHellmanPField.setText(diffieHellmanIdentity.p().toString());
        frame.diffieHellmanXField.setText(diffieHellmanIdentity.x().toString());
        frame.diffieHellmanYField.setText(diffieHellmanIdentity.y().toString());
        frame.selectedUserDiffieHellmanYField.setText("");
        frame.diffieHellmanKField.setText("");

        Runnable calculate = () -> {
            try {
                DiffieHellmanEncryption.KeyPair keyPair = diffieHellmanEncryption.calculate(
                        parsePositive(frame.diffieHellmanGField, "G"),
                        parsePositive(frame.diffieHellmanPField, "P"),
                        parsePositive(frame.diffieHellmanXField, "x")
                );
                frame.diffieHellmanYField.setText(keyPair.y().toString());
                if (!frame.selectedUserDiffieHellmanYField.getText().isBlank()) {
                    DiffieHellmanEncryption.PublicKey publicKey = new DiffieHellmanEncryption.PublicKey(
                            keyPair.g(), keyPair.p(), parsePositive(frame.selectedUserDiffieHellmanYField, "Selected user's y")
                    );
                    frame.diffieHellmanKField.setText(diffieHellmanEncryption.sharedSecret(
                            publicKey, keyPair.x(), keyPair.p(), keyPair.g()
                    ).toString());
                } else {
                    frame.diffieHellmanKField.setText("");
                }
            } catch (RuntimeException ex) {
                JOptionPane.showMessageDialog(frame, ex.getMessage(), "Invalid Diffie-Hellman values", JOptionPane.ERROR_MESSAGE);
            }
        };

        frame.diffieHellmanRandomButton.addActionListener(event -> {
            try {
                BigInteger p = parsePositive(frame.diffieHellmanPField, "P");
                frame.diffieHellmanXField.setText(diffieHellmanEncryption.randomExponent(p).toString());
                calculate.run();
            } catch (RuntimeException ex) {
                JOptionPane.showMessageDialog(frame, ex.getMessage(), "Invalid Diffie-Hellman values", JOptionPane.ERROR_MESSAGE);
            }
        });

        frame.diffieHellmanCalculateButton.addActionListener(event -> calculate.run());

        frame.diffieHellmanCopyButton.addActionListener(event -> {
            calculate.run();
            String publicValues = "G=" + frame.diffieHellmanGField.getText().trim()
                    + ", P=" + frame.diffieHellmanPField.getText().trim()
                    + ", y=" + frame.diffieHellmanYField.getText().trim();
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(publicValues), null);
        });

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

        try {
            diffieHellmanIdentity = diffieHellmanEncryption.calculate(
                    parsePositive(frame.diffieHellmanGField, "G"),
                    parsePositive(frame.diffieHellmanPField, "P"),
                    parsePositive(frame.diffieHellmanXField, "x")
            );
            if (!frame.selectedUserDiffieHellmanYField.getText().isBlank()) {
                DiffieHellmanEncryption.PublicKey publicKey = new DiffieHellmanEncryption.PublicKey(
                        diffieHellmanIdentity.g(), diffieHellmanIdentity.p(),
                        parsePositive(frame.selectedUserDiffieHellmanYField, "Selected user's y")
                );
                frame.hexKeyField.setText(diffieHellmanEncryption.toSecretKey(
                        publicKey, diffieHellmanIdentity.x(), diffieHellmanIdentity.p(), diffieHellmanIdentity.g()
                ));
            }
        } catch (RuntimeException ex) {
            JOptionPane.showMessageDialog(frame, ex.getMessage(), "Could not apply Diffie-Hellman values", JOptionPane.ERROR_MESSAGE);
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
            if (!frame.encryptionCheck.isSelected()) {
                udpService.sendPlain(text, isa);
            } else if (frame.diffieHellmanCheck.isSelected()) {
                udpService.sendDiffieHellmanEncrypted(text, frame.hexKeyField.getText().trim(), isa);
            } else {
                udpService.sendEncrypted(text, frame.hexKeyField.getText().trim(), isa);
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

            case UdpBroadcastService.ENCRYPTED_MESSAGE, UdpBroadcastService.DIFFIE_HELLMAN_ENCRYPTED_MESSAGE: {
                String text;
                try {
                    text = gcmEncryption.decrypt(message.getPayload(), frame.hexKeyField.getText().trim());
                } catch (Exception ex) {
                    ex.printStackTrace();
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
}
