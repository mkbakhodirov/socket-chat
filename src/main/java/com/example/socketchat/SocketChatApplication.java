package com.example.socketchat;

import com.google.inject.Guice;
import com.google.inject.Injector;
import com.example.socketchat.ui.ChatFrame;

import javax.swing.SwingUtilities;

public final class SocketChatApplication {

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            Injector injector = Guice.createInjector();
            ChatFrame frame = injector.getInstance(ChatFrame.class);
            frame.initialize();
            frame.setVisible(true);
        });
    }
}
