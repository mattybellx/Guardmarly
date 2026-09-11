package com.example;

import java.security.MessageDigest;

public class WeakCrypto {
    public byte[] hash(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(data);
    }
}
