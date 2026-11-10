package com.agguidigital.phishingchecker.support;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import com.sun.net.httpserver.HttpServer;

public final class MockVirusTotalServer implements AutoCloseable {

	public record RecordedRequest(String method, String path, String query, boolean dummyApiKey) {
	}

	private final HttpServer server;

	private final ExecutorService executor = Executors.newCachedThreadPool();

	private final List<RecordedRequest> requests = new CopyOnWriteArrayList<>();

	private volatile int status = 404;

	private volatile String body = "";

	private volatile Duration delay = Duration.ZERO;

	private volatile String dummyApiKey = "vt-test-key";

	private volatile int followedRedirects;

	public MockVirusTotalServer() throws IOException {
		server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
		server.createContext("/api/v3/urls/", exchange -> {
			try {
				boolean dummyApiKeyMatched = dummyApiKey.equals(exchange.getRequestHeaders().getFirst("x-apikey"));
				requests.add(new RecordedRequest(exchange.getRequestMethod(), exchange.getRequestURI().getPath(), exchange.getRequestURI().getQuery(), dummyApiKeyMatched));
				if (!delay.isZero()) {
					Thread.sleep(delay.toMillis());
				}
				byte[] payload = body.getBytes(StandardCharsets.UTF_8);
				if (status >= 300 && status < 400) {
					exchange.getResponseHeaders().set("Location", root() + "/followed");
				}
				exchange.sendResponseHeaders(status, payload.length);
				exchange.getResponseBody().write(payload);
				exchange.close();
			}
			catch (Exception ex) {
				exchange.close();
			}
		});
		server.createContext("/followed", exchange -> {
			followedRedirects++;
			exchange.sendResponseHeaders(204, -1);
			exchange.close();
		});
		server.setExecutor(executor);
		server.start();
	}

	public void respond(int status, String body) {
		this.delay = Duration.ZERO;
		this.status = status;
		this.body = body;
	}

	public void delay(Duration delay) {
		this.delay = delay;
		this.status = 200;
		this.body = "{}";
	}

	public URI root() {
		return URI.create("http://127.0.0.1:" + server.getAddress().getPort());
	}

	public List<RecordedRequest> requests() {
		return List.copyOf(requests);
	}

	public int followedRedirects() {
		return followedRedirects;
	}

	public void resetRequests() {
		requests.clear();
		followedRedirects = 0;
	}

	@Override
	public void close() {
		server.stop(0);
		executor.shutdownNow();
	}

}
