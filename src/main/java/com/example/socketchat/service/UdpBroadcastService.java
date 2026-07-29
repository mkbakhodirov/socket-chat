package com.example.socketchat.service;

import com.example.socketchat.dto.Message;
import com.example.socketchat.encryption.ElGamalEncryption;

import javax.swing.*;
import java.io.IOException;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

public final class UdpBroadcastService extends SwingWorker<Void, Object> {

    private SocketAddress broadcastAddr;
    private Consumer<Message> listener;
    private Consumer<Throwable> error;
    private DatagramSocket socket;
    private volatile boolean running;
    private final ElGamalEncryption elGamalEncryption = new ElGamalEncryption();
    private final byte[] localPublicKey;

    public static final byte HELLO = 0x00;
    public static final byte PLAIN_MESSAGE = 0x01;
    public static final byte ENCRYPTED_MESSAGE = 0x02;

    ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);

    public UdpBroadcastService(
            SocketAddress broadcastAddr,
            byte[] localPublicKey,
            Consumer<Message> listener,
            Consumer<Throwable> error
    ) {
        this.broadcastAddr = broadcastAddr;
        this.localPublicKey = localPublicKey.clone();
        this.listener = listener;
        this.error = error;

        scheduler.scheduleAtFixedRate(() -> {
            if (!running) {
                return;
            }
            sendPayload(HELLO, this.localPublicKey, broadcastAddr);
        }, 3, 30, TimeUnit.SECONDS);
    }

    @Override
    protected Void doInBackground() throws Exception {
        byte[] buffer = new byte[1500];
        DatagramPacket dp = new DatagramPacket(buffer, buffer.length);
        while (running) {
            try {
                socket.receive(dp);

                String addr = dp.getAddress().getHostAddress();
                int ofs = dp.getOffset();
                int len = dp.getLength();
                if (len < 1) {
                    continue;
                }
                byte[] data = new byte[len];
                System.arraycopy(dp.getData(), ofs, data, 0, len);

                byte type = data[0];
                int size = 0;
                byte[] payload = new byte[size];
                if (data.length > 1) {
                    size = data[1];
                    payload = new byte[size];
                    System.arraycopy(data, 2, payload, 0, size);
                }
                publish(new Message(addr, type, payload));
            } catch (IOException ex) {
                if (running) {
                    publish(ex);
                }
            }
        }

        return null;
    }

    @Override
    protected void process(List<Object> chunks) {
        for (Object chunk : chunks) {
            if (chunk instanceof Message message) {
                listener.accept(message);
            } else if (chunk instanceof Throwable throwable) {
                error.accept(throwable);
            }
        }
    }

    public synchronized void start(int port) throws SocketException {
        stop();
        socket = new DatagramSocket(null);
        socket.setReuseAddress(true);
        socket.bind(new InetSocketAddress(port));
        running = true;
        sendPayload(HELLO, localPublicKey, broadcastAddr);
    }

    public synchronized void stop() {
        running = false;
        if (socket != null) {
            socket.close();
            socket = null;
        }
    }

    public void send(String message, SocketAddress sa) {
        if (!running) {
            error.accept(new IllegalStateException("UDP is OFFLINE!!!"));
            return;
        }
        sendPayload(PLAIN_MESSAGE, message.getBytes(StandardCharsets.UTF_8), sa);
    }

    public void sendEncrypted(String message, PublicKey recipientPublicKey, SocketAddress sa) {
        if (!running) {
            error.accept(new IllegalStateException("UDP is OFFLINE!!!"));
            return;
        }
        byte[] payload;
        try {
            payload = elGamalEncryption.encrypt(message, recipientPublicKey);
        } catch (Exception ex) {
            error.accept(ex);
            return;
        }
        sendPayload(ENCRYPTED_MESSAGE, payload, sa);
    }

    private void sendPayload(byte type, byte[] payload, SocketAddress sa) {
        byte[] data = new byte[2 + payload.length];
        data[0] = type;
        data[1] = (byte) payload.length;
        System.arraycopy(payload, 0, data, 2, payload.length);

        DatagramPacket dp = new DatagramPacket(data, data.length, sa);
        try {
            socket.send(dp);
        } catch (IOException ex) {
            error.accept(ex);
        }
    }
}
