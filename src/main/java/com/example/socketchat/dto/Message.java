/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.example.socketchat.dto;

/**
 *
 * @author USER-GNK
 */
public class Message {

    final String address;
    final byte type;
    final byte[] payload;

    public Message(String address, byte type, byte[] payload) {
        this.address = address;
        this.type = type;
        this.payload = payload;
    }

    public String getAddress() {
        return address;
    }

    public byte getType() {
        return type;
    }

    public byte[] getPayload() {
        return payload;
    }

}
