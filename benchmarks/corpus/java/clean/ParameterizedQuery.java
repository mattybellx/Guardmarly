package com.example;

import java.sql.Connection;
import java.sql.PreparedStatement;
import javax.servlet.http.HttpServletRequest;

public class ParameterizedQuery {
    public void lookup(Connection conn, HttpServletRequest request) throws Exception {
        String name = request.getParameter("name");
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
        ps.setString(1, name);
        ps.executeQuery();
    }
}
