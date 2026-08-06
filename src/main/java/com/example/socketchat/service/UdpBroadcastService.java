package com.example.socketchat.service;

import com.example.socketchat.dto.Message;

import javax.swing.*;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.*;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

public final class UdpBroadcastService extends SwingWorker<Void, Object> {

    private static final int MAX_DATAGRAM_SIZE = 65_507;
    private static final int FRAME_HEADER_SIZE = 5; // type (byte) + size (int) = 5
    private static final int MAX_PAYLOAD_SIZE = MAX_DATAGRAM_SIZE - FRAME_HEADER_SIZE;

    private SocketAddress broadcastAddr;
    private Consumer<Message> listener;
    private Consumer<Throwable> error;
    private DatagramSocket socket;
    private volatile boolean running;
    public static final byte HELLO = 0x00;
    public static final byte PLAIN_MESSAGE = 0x01;
    public static final byte ENCRYPTED_MESSAGE = 0x02;
    public static final byte SIGNED_PLAIN_MESSAGE = 0x03;
    public static final byte SIGNED_ENCRYPTED_MESSAGE = 0x04;

    ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);

    public UdpBroadcastService(
            SocketAddress broadcastAddr,
            Consumer<Message> listener,
            Consumer<Throwable> error
    ) {
        this.broadcastAddr = broadcastAddr;
        this.listener = listener;
        this.error = error;

        scheduler.scheduleAtFixedRate(() -> {
            if (!running) {
                return;
            }
            send(HELLO, new byte[0], broadcastAddr);
        }, 3, 3, TimeUnit.SECONDS);
    }

    @Override
    protected Void doInBackground() throws Exception {
        byte[] buffer = new byte[MAX_DATAGRAM_SIZE];
        DatagramPacket dp = new DatagramPacket(buffer, buffer.length);
        while (running) {
            try {
                dp.setLength(buffer.length);
                socket.receive(dp);

                String addr = dp.getAddress().getHostAddress();
//                if (addr.equals("172.19.236.72")) {
//                    return null;
//                }
                int ofs = dp.getOffset();
                int len = dp.getLength();
                if (len < FRAME_HEADER_SIZE) {
                    continue;
                }
                byte[] data = new byte[len];
                System.arraycopy(dp.getData(), ofs, data, 0, len);
                System.out.println("Received data from " + addr + ": " + Arrays.toString(data));

                byte type;
                byte[] payload;
                try (ByteArrayInputStream input = new ByteArrayInputStream(data);
                     DataInputStream stream = new DataInputStream(input)) {
                    type = stream.readByte();
                    int size = stream.readInt();
                    if (size < 0 || size != stream.available()) {
                        throw new IllegalArgumentException("Invalid UDP payload length: " + size);
                    }
                    payload = stream.readNBytes(size);
                }
                publish(new Message(addr, type, payload));
            } catch (Exception ex) {
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
        if (running) {
            throw new IllegalStateException("UDP service is already running");
        }
        socket = new DatagramSocket(null);
        socket.setReuseAddress(true);
        socket.bind(new InetSocketAddress(port));
        running = true;
        send(HELLO, new byte[0], broadcastAddr);
    }

    public synchronized void stop() {
        running = false;
        if (socket != null) {
            socket.close();
            socket = null;
        }
        scheduler.shutdownNow();
    }

    public void send(byte type, byte[] payload, SocketAddress sa) {
        if (!running) {
            error.accept(new IllegalStateException("UDP is OFFLINE!!!"));
            return;
        }
        if (payload == null) {
            error.accept(new IllegalArgumentException("UDP payload must not be null"));
            return;
        }
        if (payload.length > MAX_PAYLOAD_SIZE) {
            error.accept(new IllegalArgumentException(
                    "UDP payload must not exceed " + MAX_PAYLOAD_SIZE + " bytes"
            ));
            return;
        }
        try {
            byte[] data;
            try (ByteArrayOutputStream output = new ByteArrayOutputStream(FRAME_HEADER_SIZE + payload.length);
                 DataOutputStream stream = new DataOutputStream(output)) {
                stream.writeByte(type);
                stream.writeInt(payload.length);
                stream.write(payload);
                data = output.toByteArray();
            }
            System.out.println("Sent data: " + Arrays.toString(data));

            DatagramPacket dp = new DatagramPacket(data, data.length, sa);
            socket.send(dp);
        } catch (Exception ex) {
            publish(ex);
        }
    }
}
