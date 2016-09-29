package com.picoto.ssl;

import java.util.ResourceBundle;

public class KeyStoreConfiguration {
    
    private static final ResourceBundle bundle = ResourceBundle.getBundle("connection-security");

    private String path;
    
    private String password;
    
    private String type;
    
    private String alias;
   
    public KeyStoreConfiguration(String path, String password, String type, String alias) {
        super();
        this.path = path;
        this.password = password;
        this.type = type;
        this.alias = alias;
    }
    
    

    public KeyStoreConfiguration(String path, String password, String type) {
        super();
        this.path = path;
        this.password = password;
        this.type = type;
    }



    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getAlias() {
        return alias;
    }

    public void setAlias(String alias) {
        this.alias = alias;
    }



    public boolean isFile() {
        return path != null && path.startsWith(bundle.getString("file.prefix"));
    }
    
    public String getFilePath() {
        if (path == null) {
            return "";
        } else {
            return path.substring(bundle.getString("file.prefix").length());
        }
    }
    
    

}
