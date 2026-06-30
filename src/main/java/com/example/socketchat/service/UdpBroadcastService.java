package com.example.socketchat.service;

import com.example.socketchat.model.ChatMessage;
import com.google.inject.Singleton;

import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketException;
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
}
