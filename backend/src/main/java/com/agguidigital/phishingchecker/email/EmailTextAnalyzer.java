package com.agguidigital.phishingchecker.email;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Deterministic text rules. This does not fetch URLs, read headers, or score a probability.
 */
public final class EmailTextAnalyzer {

	public static final String CREDENTIAL_REQUEST = "credential_request";

	public static final String GIFT_CARD_PAYMENT = "gift_card_payment";

	public static final String URGENCY_OR_THREAT = "urgency_or_threat";

	public static final String NEGATED_SECRET_REQUEST = "negated_secret_request";

	public static final String CREDENTIAL_EXPLANATION = "The text asks for a password, passcode, or verification code.";

	public static final String GIFT_CARD_EXPLANATION = "The text asks for a gift-card payment or a gift-card code.";

	public static final String URGENCY_EXPLANATION = "The text uses urgency or threat language. That alone is not treated as suspicion.";

	public static final String NEGATED_EXPLANATION = "A password, code, or gift-card instruction is explicitly negated, so it is not treated as a request.";

	public static final String MISSED_THREATS_LIMITATION = "Text-only rules can miss threats and can flag legitimate messages.";

	public static final String SCOPE_LIMITATION = "This endpoint does not analyze email headers, attachments, or link reputation.";

	private static final String SECRET = "(?:password|passcode|pass code|verification code|security code|one-time code|one time code|otp|pin code|pin)";

	private static final String GIFT_CARD = "(?:gift\\s*cards?|google\\s+play\\s+cards?|itunes\\s+cards?|apple\\s+gift\\s+cards?|steam\\s+cards?)";

	private static final Pattern IMMEDIATE_NEGATION = Pattern.compile(
			"(?:never|do not|don't|dont|will not|won't|wont|cannot|can't|cant)\\s+(?:please\\s+|you\\s+|to\\s+|ever\\s+)?$");

	private static final Pattern CREDENTIAL_REQUEST_PATTERN = Pattern.compile(
			"\\b(?:send|share|provide|enter|submit|type|disclose)\\s+(?:me\\s+|us\\s+)?(?:your\\s+|the\\s+|a\\s+|an\\s+)?" + SECRET + "\\b"
					+ "|\\b(?:reply with|ask for)\\s+(?:your\\s+|the\\s+|a\\s+)?" + SECRET + "\\b"
					+ "|\\b(?:give|tell)\\s+me\\s+(?:your\\s+|the\\s+)?" + SECRET + "\\b"
					+ "|\\b(?:what is your|what's your|whats your)\\s+" + SECRET + "\\b"
					+ "|\\bconfirm\\s+your\\s+" + SECRET + "\\b");

	private static final Pattern GIFT_CARD_PATTERN = Pattern.compile(
			"\\b(?:buy|purchase)\\s+(?:[a-z0-9]+\\s+){0,4}" + GIFT_CARD + "\\b"
					+ "|\\bpay\\s+(?:with|using)\\s+(?:a\\s+|an\\s+)?(?:[a-z]+\\s+){0,3}" + GIFT_CARD + "\\b"
					+ "|\\bsend\\s+(?:me\\s+|us\\s+)?(?:the\\s+|your\\s+)?" + GIFT_CARD + "\\s+codes?\\b"
					+ "|\\bsend\\s+(?:me\\s+|us\\s+)?(?:the\\s+|your\\s+)?codes?\\b");

	private static final Pattern URGENCY_PATTERN = Pattern.compile(
			"\\burgent(?:ly)?\\b|\\bimmediately\\b|\\bact now\\b|\\bright away\\b|\\bfinal notice\\b|\\blast warning\\b"
					+ "|\\blegal action\\b|\\blimited time\\b|\\bor else\\b|\\bwithin \\d+ hours?\\b"
					+ "|\\baccount (?:will be|has been|is) (?:closed|suspended|locked|terminated|deleted)\\b");

	private EmailTextAnalyzer() {
	}

	public static EmailAnalysisResponse analyze(String text) {
		String normalized = normalize(text);
		boolean credentialRequest = hasActive(normalized, CREDENTIAL_REQUEST_PATTERN);
		boolean giftCardPayment = hasGiftCardRequest(normalized);
		boolean urgency = URGENCY_PATTERN.matcher(normalized).find();
		boolean negated = hasNegated(normalized, CREDENTIAL_REQUEST_PATTERN) || hasNegatedGiftCard(normalized);

		List<EmailFinding> findings = new ArrayList<>();
		if (credentialRequest) {
			findings.add(new EmailFinding(CREDENTIAL_REQUEST, CREDENTIAL_EXPLANATION));
		}
		if (giftCardPayment) {
			findings.add(new EmailFinding(GIFT_CARD_PAYMENT, GIFT_CARD_EXPLANATION));
		}
		if (urgency) {
			findings.add(new EmailFinding(URGENCY_OR_THREAT, URGENCY_EXPLANATION));
		}
		if (negated) {
			findings.add(new EmailFinding(NEGATED_SECRET_REQUEST, NEGATED_EXPLANATION));
		}

		EmailAssessment assessment;
		if (credentialRequest || giftCardPayment) {
			assessment = EmailAssessment.suspicious;
		}
		else if (urgency) {
			assessment = EmailAssessment.inconclusive;
		}
		else {
			assessment = EmailAssessment.no_obvious_warning_signs;
		}
		return new EmailAnalysisResponse(assessment, findings, limitations());
	}

	public static List<String> limitations() {
		return List.of(MISSED_THREATS_LIMITATION, SCOPE_LIMITATION);
	}

	private static String normalize(String text) {
		return text.toLowerCase(Locale.ROOT).replace('\u2019', '\'');
	}

	private static boolean hasActive(String text, Pattern pattern) {
		Matcher matcher = pattern.matcher(text);
		while (matcher.find()) {
			if (!isNegated(text, matcher.start())) {
				return true;
			}
		}
		return false;
	}

	private static boolean hasNegated(String text, Pattern pattern) {
		Matcher matcher = pattern.matcher(text);
		while (matcher.find()) {
			if (isNegated(text, matcher.start())) {
				return true;
			}
		}
		return false;
	}

	private static boolean hasNegatedGiftCard(String text) {
		Matcher matcher = GIFT_CARD_PATTERN.matcher(text);
		while (matcher.find()) {
			if (!isBareCodeShare(text, matcher) && isNegated(text, matcher.start())) {
				return true;
			}
		}
		return false;
	}

	private static boolean hasGiftCardRequest(String text) {
		Matcher matcher = GIFT_CARD_PATTERN.matcher(text);
		while (matcher.find()) {
			if (isBareCodeShare(text, matcher) || isNegated(text, matcher.start())) {
				continue;
			}
			return true;
		}
		return false;
	}

	private static boolean isBareCodeShare(String text, Matcher matcher) {
		String matched = matcher.group();
		if (!matched.startsWith("send") || matched.contains("gift")) {
			return false;
		}
		int sentenceStart = Math.max(
				text.lastIndexOf('.', matcher.start() - 1),
				Math.max(text.lastIndexOf('!', matcher.start() - 1), text.lastIndexOf('?', matcher.start() - 1)));
		int sentenceEnd = indexOfSentenceEnd(text, matcher.end());
		String sentence = text.substring(sentenceStart + 1, sentenceEnd);
		return !sentence.contains("gift card") && !sentence.contains("giftcard")
				&& !sentence.contains("google play card") && !sentence.contains("itunes card")
				&& !sentence.contains("steam card");
	}

	private static int indexOfSentenceEnd(String text, int from) {
		int end = text.length();
		for (int i = from; i < text.length(); i++) {
			char character = text.charAt(i);
			if (character == '.' || character == '!' || character == '?') {
				return i;
			}
		}
		return end;
	}

	private static boolean isNegated(String text, int matchStart) {
		int from = Math.max(0, matchStart - 40);
		return IMMEDIATE_NEGATION.matcher(text.substring(from, matchStart)).find();
	}

}
