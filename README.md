# Socket Chat

Socket Chat is a desktop peer-to-peer chat application for devices on the same local network. It discovers peers with UDP broadcast messages and sends messages directly to a selected IP address. Messages can be sent as plain text or protected with AES-GCM using either a manually shared key or a key derived through Diffie-Hellman.

There is no central chat server: every running instance listens for UDP packets and also acts as a sender.

## Technology

- Java 21
- Java Swing desktop UI
- UDP datagrams and LAN broadcast for peer discovery
- AES-GCM authenticated encryption
- Diffie-Hellman key exchange with `BigInteger` modular arithmetic
- Google Guice 5.1 for dependency injection
- Maven for building and running the application

### How it works

Each client broadcasts a small presence packet every three seconds. Other clients add the sender's IP address to the **ADDRESSES** list; an address is removed if it has not been seen for about one minute. Chat messages are then sent directly to the selected address over the configured UDP port.

The application supports these packet types:

- Presence/hello
- Plain UTF-8 message
- AES-GCM encrypted message
- Diffie-Hellman-derived AES-GCM encrypted message

UDP message payload lengths are encoded as 32-bit integers. A single application datagram can carry up to 65,502 payload bytes, although large UDP datagrams may be fragmented or dropped by the network.

## Requirements

- JDK 21 or newer
- Apache Maven 3.9 or newer
- Two or more computers on the same LAN for normal peer-to-peer use
- Permission for the selected UDP port in the operating-system firewall

Check the installed tools:

```shell
java -version
mvn -version
```

## Run

Clone the repository and open its directory:

```shell
git clone <repository-url>
cd socket-chat
```

Compile the project:

```shell
mvn clean package
```

Start the application:

```shell
mvn exec:java
```

Run the same command on each computer that should participate in the chat. All instances must use the same UDP port. The default configuration is:

- Broadcast address: `255.255.255.255`
- UDP port: `9000`
- Listener: enabled

If peer discovery does not work, allow inbound and outbound UDP traffic on port `9000`, verify that the devices are on the same LAN, and try the subnet-specific broadcast address supplied by the network (for example, `192.168.1.255`). Some routers and guest Wi-Fi networks block communication between clients.

## Using the UI

### 1. Start peer discovery

1. Enter the LAN broadcast address in **BROADCAST IP ADDRESS**.
2. Enter the same value in **UDP PORT** on every client.
3. Select **START**. The status changes to `* LISTENING`.
4. Wait a few seconds for peer IP addresses to appear under **ADDRESSES**.

Configure the address and port before starting. To apply a changed listening configuration, clear **START** and select it again.

### 2. Send a plain message

1. Leave **Encryption** cleared.
2. Select a peer in the **ADDRESSES** list.
3. Type in the field at the bottom.
4. Press **Enter** or click **Send**.

Received messages appear in **MESSAGES** with a timestamp, direction marker, sender IP, and message text.

### 3. Send an encrypted message with a shared key

1. Select **Encryption**. A random AES key is generated in **HEX KEY**.
2. Securely copy the same key to the **HEX KEY** field on the other client.
3. Keep **Diffie-Hellman Key Exchange** cleared.
4. Select a peer and send the message normally.

Every participant must use exactly the same hexadecimal key. Valid AES keys contain 32, 48, or 64 hexadecimal characters (128, 192, or 256 bits). A client with a different key will show a decryption error.

### 4. Derive a key with Diffie-Hellman

Perform these steps on both clients:

1. Select **Diffie-Hellman Key Exchange**. Encryption is enabled automatically.
2. Click **View Diffie-Hellman**.
3. Keep the same `G` and `P` values on both clients. The defaults are already identical.
4. Optionally click **Random x** to create a new private exponent.
5. Click **Copy public values** and send `G`, `P`, and `y` to the other user through a separate channel. Never share `x`.
6. Paste the other user's `y` into **Selected user's y**.
7. Click **Calculate**. Both clients should derive the same `K` value.
8. Click **OK** to apply the derived value as the AES key in **HEX KEY**.
9. Select the peer and send messages normally.

This is a manual, unauthenticated Diffie-Hellman exchange intended for learning. Verify the public values through a trusted channel; otherwise, the exchange can be vulnerable to a man-in-the-middle attack.

## Project structure

```text
src/main/java/com/example/socketchat/
|-- SocketChatApplication.java       Application entry point
|-- dto/Message.java                 Decoded UDP packet
|-- encryption/
|   |-- GcmEncryption.java           AES-GCM key generation and encryption
|   `-- DiffieHellmanEncryption.java Diffie-Hellman calculations
|-- model/                           Peer and chat data models
|-- service/UdpBroadcastService.java UDP discovery, receive, and send logic
`-- ui/
    |-- MainFrame.java               Swing interface
    `-- Controller.java              UI behavior and application coordination
```

## Notes and limitations

- The application is designed for a trusted local network and does not relay traffic across the internet.
- UDP delivery is best-effort; packets can be lost, duplicated, or reordered.
- Peer identity is represented by IP address only.
- Sent messages are not added to the local message history; the message area displays received messages and errors.
- There is no persistent chat history or user account system.
- Diffie-Hellman public values are exchanged manually and are not authenticated.
