package com.picoto.ws.security;

public class SecurityHandlerException extends RuntimeException {

    private static final long serialVersionUID = 5544438331875498008L;

    public SecurityHandlerException() {
        super();
    }

    public SecurityHandlerException(String str, Throwable t) {
        super(str, t);
    }

    public SecurityHandlerException(String s) {
        super(s);
    }

    public SecurityHandlerException(Throwable t) {
        super(t);
    }

}
