/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.example.socketchat.model;

import java.time.LocalTime;

/**
 *
 * @author administrator
 */
public class User {

    LocalTime time;

    String address;

    public User(LocalTime time, String address) {
        this.time = time;
        this.address = address;
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

    @Override
    public String toString() {
        return address;
    }

}
