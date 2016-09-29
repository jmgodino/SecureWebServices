Usage:

    @SuppressWarnings("rawtypes")
    public static void main(String args[]) {

        try {
            MyWebService ws = new MyWebService();
            MyWebServicePort inv = ws.getMyWebServicePort();
            BindingProvider bp = (BindingProvider) inv;
            List<Handler> handlers = new ArrayList<Handler>();
            handlers.add(new JAXWSSSLHandler()); //Just in case you're using JAX-WS without Axis
            handlers.add(new SecurityHandler(false, true, true, true));
            handlers.add(new LogHandler());
            bp.getBinding().setHandlerChain(handlers);
            
            inv.myFunction("Hello world!");
        } catch (Exception e) {
            e.printStackTrace();
        }

    }
    
    
1.- Load client certificate en wallets/client.jks2
2.- Load server's issuer certificates in wallets/server.jks
3.- Change in env/desarrollo/environment.properties the values for ks.password and ts.password encripted with AES (currently changeit). Example:
 
        AESCipher c = new AESCipher();
        System.out.println(c.encrypt("changeit"));

The seed used is configured in: src/main/resources/connection-security.properties property secret.key

4.- Change the alias of the client's certificate in file env/desarrollo/environment.properties:

ks.alias=cliente.test.desa