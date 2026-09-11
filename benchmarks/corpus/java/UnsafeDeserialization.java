package com.example;

import java.io.ObjectInputStream;
import javax.servlet.http.HttpServletRequest;

public class UnsafeDeserialization {
    public Object load(HttpServletRequest request) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
        return ois.readObject();
    }
}
