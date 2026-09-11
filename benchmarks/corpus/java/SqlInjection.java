package com.example;

import java.sql.Connection;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

public class SqlInjection {
    public void lookup(Connection conn, HttpServletRequest request) throws Exception {
        String name = request.getParameter("name");
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
    }
}
