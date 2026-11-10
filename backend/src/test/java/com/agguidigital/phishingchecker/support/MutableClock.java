package com.agguidigital.phishingchecker.support;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;

public final class MutableClock extends Clock {

	private Instant instant;

	public MutableClock(Instant instant) {
		this.instant = instant;
	}

	public synchronized void plus(Duration duration) {
		instant = instant.plus(duration);
	}

	@Override
	public ZoneId getZone() {
		return ZoneOffset.UTC;
	}

	@Override
	public Clock withZone(ZoneId zone) {
		return this;
	}

	@Override
	public synchronized Instant instant() {
		return instant;
	}

}
