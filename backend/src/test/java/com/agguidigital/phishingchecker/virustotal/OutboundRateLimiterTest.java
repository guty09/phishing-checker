package com.agguidigital.phishingchecker.virustotal;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import com.agguidigital.phishingchecker.support.MutableClock;

import static org.assertj.core.api.Assertions.assertThat;

class OutboundRateLimiterTest {

	@Test
	void allowsFourRequestsInARollingMinute() {
		MutableClock clock = new MutableClock(Instant.parse("2026-01-01T00:00:00Z"));
		OutboundRateLimiter limiter = new OutboundRateLimiter(4, Duration.ofSeconds(60), clock);

		assertThat(limiter.tryAcquire()).isTrue();
		assertThat(limiter.tryAcquire()).isTrue();
		assertThat(limiter.tryAcquire()).isTrue();
		assertThat(limiter.tryAcquire()).isTrue();
		assertThat(limiter.tryAcquire()).isFalse();

		clock.plus(Duration.ofSeconds(59));
		assertThat(limiter.tryAcquire()).isFalse();

		clock.plus(Duration.ofSeconds(1));
		assertThat(limiter.tryAcquire()).isTrue();
	}

	@Test
	void capsConcurrentAcquiresAtFour() throws Exception {
		OutboundRateLimiter limiter = new OutboundRateLimiter(4, Duration.ofSeconds(60), new MutableClock(Instant.parse("2026-01-01T00:00:00Z")));
		ExecutorService pool = Executors.newFixedThreadPool(8);
		CountDownLatch start = new CountDownLatch(1);
		AtomicInteger allowed = new AtomicInteger();
		List<Future<?>> futures = new ArrayList<>();
		try {
			for (int i = 0; i < 32; i++) {
				futures.add(pool.submit(() -> {
					start.await();
					if (limiter.tryAcquire()) {
						allowed.incrementAndGet();
					}
					return null;
				}));
			}
			start.countDown();
			for (Future<?> future : futures) {
				future.get();
			}
		}
		finally {
			pool.shutdownNow();
		}
		assertThat(allowed).hasValue(4);
	}

}
