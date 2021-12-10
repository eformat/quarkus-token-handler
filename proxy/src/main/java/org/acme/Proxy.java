package org.acme;

import io.quarkus.runtime.StartupEvent;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.*;
import io.vertx.core.net.PemKeyCertOptions;
import io.vertx.core.net.ProxyOptions;
import io.vertx.core.net.ProxyType;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.proxy.handler.ProxyHandler;
import io.vertx.httpproxy.HttpProxy;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.event.Observes;
import javax.inject.Inject;
import java.util.Set;

@ApplicationScoped
public class Proxy {

    private final Logger log = LoggerFactory.getLogger(Proxy.class);

    @Inject
    Vertx vertx;

    @Inject
    Util util;

    @ConfigProperty(name = "proxyServerHttpPort")
    int proxyServerHttpPort;

    @ConfigProperty(name = "proxyServerHttpsPort")
    int proxyServerHttpsPort;

    @ConfigProperty(name = "tokenHandlerPort")
    int tokenHandlerPort;

    @ConfigProperty(name = "tokenHandlerService")
    String tokenHandlerService;

    @ConfigProperty(name = "proxyService")
    String proxyService;

    @ConfigProperty(name = "apiHandlerPort")
    int apiHandlerPort;

    @ConfigProperty(name = "apiHandlerService")
    String apiHandlerService;

    void onStart(@Observes StartupEvent ev) {
        httpProxy();
        httpsProxy();
    }

    /*
        We cannot man in the middle ssl easily here. Pass to backend unencrypted for now.
     */
    private void httpsProxy() {

        HttpClient proxyClient = vertx.createHttpClient();
        Router proxyRouter = Router.router(vertx);

        Buffer key = vertx.fileSystem().readFileBlocking("example.server.key");
        Buffer cert = vertx.fileSystem().readFileBlocking("example.server.pem");

        ProxyOptions proxyOptions = new ProxyOptions();
        proxyOptions.setType(ProxyType.HTTP);

        HttpProxy tokenProxy = HttpProxy.reverseProxy(proxyClient);
        tokenProxy.origin(proxyServerHttpPort, tokenHandlerService);

        HttpProxy apiProxy = HttpProxy.reverseProxy(proxyClient);
        apiProxy.origin(apiHandlerPort, apiHandlerService);

        proxyRouter.route("/api/*").handler(event -> {
            if (event.request().cookies("example-auth") != null) {
                Set<Cookie> cookies = event.request().cookies("example-at");
                if (!cookies.isEmpty()) {
                    String decrytedCookie = util.decryptCookieValue(cookies.iterator().next().getValue());
                    event.request().headers().add("Authorization", "Bearer " + decrytedCookie);
                }
            }
            event.next();
        });

        proxyRouter
                .route("/tokenhandler/*").handler(ProxyHandler.create(tokenProxy));
        proxyRouter
                .route("/tokenhandler/*").handler(ProxyHandler.create(tokenProxy));
        proxyRouter
                .route("/api/*").handler(ProxyHandler.create(apiProxy));
        proxyRouter
                .route("/api/*").handler(ProxyHandler.create(apiProxy));

        HttpServerOptions serverOptions = new HttpServerOptions();
        serverOptions.setSsl(true);
        serverOptions.setPemKeyCertOptions(new PemKeyCertOptions().setKeyValue(key).setCertValue(cert));
        serverOptions.setLogActivity(true);
        serverOptions.setUseAlpn(true);

        HttpServer proxyServer = vertx.createHttpServer(serverOptions);
        proxyServer.requestHandler(proxyRouter).listen(proxyServerHttpsPort);

        log.info(">>> HTTPS Proxy started");

    }

    private void httpProxy() {

        HttpServer proxyServer = vertx.createHttpServer();
        HttpClient proxyClient = vertx.createHttpClient();
        Router proxyRouter = Router.router(vertx);

        HttpProxy tokenProxy = HttpProxy.reverseProxy(proxyClient);
        tokenProxy.origin(tokenHandlerPort, tokenHandlerService);

        HttpProxy apiProxy = HttpProxy.reverseProxy(proxyClient);
        apiProxy.origin(apiHandlerPort, apiHandlerService);

        proxyRouter.route("/api/*").handler(event -> {
            if (event.request().cookies("example-auth") != null) {
                Set<Cookie> cookies = event.request().cookies("example-at");
                if (!cookies.isEmpty()) {
                    String decrytedCookie = util.decryptCookieValue(cookies.iterator().next().getValue());
                    event.request().headers().add("Authorization", "Bearer " + decrytedCookie);
                }
            }
            event.next();
        });

        proxyRouter
                .route("/tokenhandler/*").handler(ProxyHandler.create(tokenProxy));
        proxyRouter
                .route("/tokenhandler/*").handler(ProxyHandler.create(tokenProxy));
        proxyRouter
                .route("/api/*").handler(ProxyHandler.create(apiProxy));
        proxyRouter
                .route("/api/*").handler(ProxyHandler.create(apiProxy));

        proxyServer.requestHandler(proxyRouter);
        proxyServer.listen(proxyServerHttpPort);

        log.info(">>> HTTP Proxy started");
    }
}
