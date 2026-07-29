/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.example.socketchat.model;

import java.time.LocalTime;
import java.util.Arrays;

/**
 *
 * @author administrator
 */
public class User {

    LocalTime time;

    String address;

    byte[] publicKey;

    public User(LocalTime time, String address, byte[] publicKey) {
        this.time = time;
        this.address = address;
        this.publicKey = publicKey;
    }

    public LocalTime getTime() {
        return time;
    }

    public void setTime(LocalTime time) {
        this.time = time;
    }

    public String getAddress() {
        return address;
    }

    public byte[] getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(byte[] publicKey) {
        this.publicKey = publicKey;
    }

    public boolean hasPublicKey(byte[] publicKey) {
        return Arrays.equals(this.publicKey, publicKey);
    }

    @Override
    public String toString() {
        return address;
    }

}
