package com.example;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class OpenRedirect {
    public void go(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String next = request.getParameter("next");
        response.sendRedirect(next);
    }
}
