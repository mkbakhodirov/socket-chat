package com.example.socketchat.model;

import java.time.LocalTime;

public record ChatMessage(LocalTime time, String direction, String sender, String text) {
}
