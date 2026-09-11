package com.example;

import java.io.File;
import java.io.FileInputStream;
import javax.servlet.http.HttpServletRequest;

public class PathTraversal {
    public byte[] read(HttpServletRequest request) throws Exception {
        String name = request.getParameter("file");
        File f = new File("/srv/files/" + name);
        FileInputStream in = new FileInputStream(f);
        return in.readAllBytes();
    }
}
