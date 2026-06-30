package com.example.socketchat;

import com.example.socketchat.ui.Controller;
import com.google.inject.Guice;
import com.google.inject.Injector;

import javax.swing.*;

public final class SocketChatApplication {

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            Injector injector = Guice.createInjector();

            Controller controller = injector.getInstance(Controller.class);
            controller.run();
        });
    }
}
