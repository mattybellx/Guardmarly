package com.example;

import java.security.MessageDigest;

public class StrongCrypto {
    public byte[] hash(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(data);
    }
}
