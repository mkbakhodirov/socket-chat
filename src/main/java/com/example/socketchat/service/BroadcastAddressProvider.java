package com.example.socketchat.service;

import com.example.socketchat.model.BroadcastAddress;
import com.google.inject.Singleton;

import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.List;

@Singleton
public final class BroadcastAddressProvider {
    public List<BroadcastAddress> findBroadcastAddresses() {
        List<BroadcastAddress> addresses = new ArrayList<>();
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                NetworkInterface networkInterface = interfaces.nextElement();
                if (networkInterface.isLoopback() || !networkInterface.isUp()) {
                    continue;
                }

                for (InterfaceAddress interfaceAddress : networkInterface.getInterfaceAddresses()) {
                    if (interfaceAddress.getAddress() != null && interfaceAddress.getBroadcast() != null) {
                        addresses.add(new BroadcastAddress(
                                interfaceAddress.getBroadcast().getHostAddress(),
                                interfaceAddress.getAddress().getHostAddress()
                        ));
                    }
                }
            }
        } catch (SocketException ignored) {
            // Fall through to default broadcast address.
        }

        if (addresses.isEmpty()) {
            addresses.add(new BroadcastAddress("255.255.255.255", "127.0.0.1"));
        }

        return addresses.stream()
                .sorted(Comparator.comparing(BroadcastAddress::hostAddress))
                .toList();
    }
}
