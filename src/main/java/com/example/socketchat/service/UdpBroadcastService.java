package com.example.socketchat.service;

import com.example.socketchat.model.ChatMessage;
import com.google.inject.Singleton;

import javax.swing.*;
import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.time.LocalTime;
import java.util.function.Consumer;

@Singleton
public final class UdpBroadcastService {

    private Consumer<ChatMessage> listener;
    private DatagramSocket socket;
    private volatile boolean running;

    public UdpBroadcastService() {
    }

    public synchronized void start(int port) throws SocketException {
        stop();
        socket = new DatagramSocket(null);
        socket.setReuseAddress(true);
        socket.bind(new InetSocketAddress(port));
        running = true;
    }

    public synchronized void stop() {
        running = false;
        if (socket != null) {
            socket.close();
            socket = null;
        }
    }

    public void addListener(Consumer<ChatMessage> listener) {
        this.listener = listener;
    }

    public void send(String host, int port, String text) throws IOException {
        publish(new ChatMessage(LocalTime.now(), "->", host + ":" + port, text));
    }

    private void publish(ChatMessage message) {
        SwingUtilities.invokeLater(() -> {
            if (listener != null) {
                listener.accept(message);
            }
        });
    }
}
