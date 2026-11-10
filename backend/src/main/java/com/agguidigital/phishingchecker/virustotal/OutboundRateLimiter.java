package com.agguidigital.phishingchecker.virustotal;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;

public final class OutboundRateLimiter {

	private final int maxRequests;
	private final Duration window;
	private final Clock clock;
	private final Deque<Instant> timestamps = new ArrayDeque<>();

	public OutboundRateLimiter(int maxRequests, Duration window, Clock clock) {
		if (maxRequests < 1) {
			throw new IllegalArgumentException("maxRequests must be positive");
		}
		this.maxRequests = maxRequests;
		this.window = window;
		this.clock = clock;
	}

	public synchronized boolean tryAcquire() {
		Instant now = clock.instant();
		Instant cutoff = now.minus(window);
		while (!timestamps.isEmpty() && !timestamps.peekFirst().isAfter(cutoff)) {
			timestamps.removeFirst();
		}
		if (timestamps.size() >= maxRequests) {
			return false;
		}
		timestamps.addLast(now);
		return true;
	}

}
