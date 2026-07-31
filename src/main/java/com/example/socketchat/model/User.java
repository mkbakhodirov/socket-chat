/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.example.socketchat.model;

import com.example.socketchat.encryption.DiffieHellmanEncryption;
import com.example.socketchat.encryption.ElGamalEncryption.PublicKey;

import java.time.LocalTime;

/**
 *
 * @author administrator
 */
public class User {

    LocalTime time;

    String address;

    PublicKey publicKey;

    DiffieHellmanEncryption.PublicKey diffieHellmanPublicKey;

    public User(LocalTime time, String address, PublicKey publicKey, DiffieHellmanEncryption.PublicKey diffieHellmanPublicKey) {
        this.time = time;
        this.address = address;
        this.publicKey = publicKey;
        this.diffieHellmanPublicKey = diffieHellmanPublicKey;
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

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public DiffieHellmanEncryption.PublicKey getDiffieHellmanPublicKey() {
        return diffieHellmanPublicKey;
    }

    public void setDiffieHellmanPublicKey(DiffieHellmanEncryption.PublicKey diffieHellmanPublicKey) {
        this.diffieHellmanPublicKey = diffieHellmanPublicKey;
    }

    @Override
    public String toString() {
        return address;
    }
}
