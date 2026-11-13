package com.agguidigital.phishingchecker.support;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import com.sun.net.httpserver.HttpServer;

public final class MockPhishTankServer implements AutoCloseable {

	public record RecordedRequest(String method, String path, String query, String contentType, String userAgent, String body) {
	}

	private final HttpServer server;

	private final ExecutorService executor = Executors.newCachedThreadPool();

	private final List<RecordedRequest> requests = new CopyOnWriteArrayList<>();

	private volatile int status = 200;

	private volatile String body = "";

	private volatile Duration delay = Duration.ZERO;

	private volatile Map<String, String> headers = Map.of();

	private volatile int followedRedirects;

	public MockPhishTankServer() throws IOException {
		server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
		server.createContext("/", exchange -> {
			try {
				String requestBody = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
				requests.add(new RecordedRequest(
						exchange.getRequestMethod(),
						exchange.getRequestURI().getPath(),
						exchange.getRequestURI().getRawQuery(),
						exchange.getRequestHeaders().getFirst("Content-Type"),
						exchange.getRequestHeaders().getFirst("User-Agent"),
						requestBody));
				if (!delay.isZero()) {
					Thread.sleep(delay.toMillis());
				}
				headers.forEach((name, value) -> exchange.getResponseHeaders().set(name, value));
				if (status >= 300 && status < 400) {
					exchange.getResponseHeaders().set("Location", endpoint().resolve("followed").toString());
					exchange.sendResponseHeaders(status, -1);
					exchange.close();
					return;
				}
				byte[] payload = body.getBytes(StandardCharsets.UTF_8);
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
		respond(status, body, Map.of());
	}

	public void respond(int status, String body, Map<String, String> headers) {
		this.delay = Duration.ZERO;
		this.status = status;
		this.body = body;
		this.headers = Map.copyOf(headers);
	}

	public void delay(Duration delay) {
		this.delay = delay;
		this.status = 200;
		this.body = "{\"results\":{\"in_database\":false}}";
		this.headers = Map.of();
	}

	public URI endpoint() {
		return URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/checkurl/");
	}

	public List<RecordedRequest> requests() {
		return List.copyOf(requests);
	}

	public int followedRedirects() {
		return followedRedirects;
	}

	@Override
	public void close() {
		server.stop(0);
		executor.shutdownNow();
	}

}
