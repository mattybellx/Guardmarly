package com.example;

import javax.servlet.http.HttpServletResponse;

public class ConstantRedirect {
    public void go(HttpServletResponse response) throws Exception {
        response.sendRedirect("/home");
    }
}
