package com.example;

import javax.servlet.http.HttpServletRequest;

public class CommandInjection {
    public void ping(HttpServletRequest request) throws Exception {
        String host = request.getParameter("host");
        Runtime.getRuntime().exec("ping -c 1 " + host);
    }
}
