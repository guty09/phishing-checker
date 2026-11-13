package com.agguidigital.phishingchecker.email;

import java.util.List;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class EmailTextAnalyzerTest {

	@Test
	void flagsPasswordAndVerificationCodeRequestsAsSuspicious() {
		EmailAnalysisResponse password = EmailTextAnalyzer.analyze(
				"Your mailbox is full. Reply with your password so we can reopen it.");
		EmailAnalysisResponse code = EmailTextAnalyzer.analyze(
				"Enter the verification code from the message and submit it here.");

		assertThat(password.assessment()).isEqualTo(EmailAssessment.suspicious);
		assertThat(ruleIds(password)).contains(EmailTextAnalyzer.CREDENTIAL_REQUEST);
		assertThat(code.assessment()).isEqualTo(EmailAssessment.suspicious);
		assertThat(ruleIds(code)).contains(EmailTextAnalyzer.CREDENTIAL_REQUEST);
		assertThat(password.findings()).allSatisfy(finding -> assertThat(finding.explanation())
				.doesNotContainIgnoringCase("confirmed")
				.doesNotContainIgnoringCase("probability"));
	}

	@Test
	void flagsGiftCardPaymentRequestsAsSuspicious() {
		EmailAnalysisResponse response = EmailTextAnalyzer.analyze(
				"Buy two Apple gift cards and send the codes right away.");

		assertThat(response.assessment()).isEqualTo(EmailAssessment.suspicious);
		assertThat(ruleIds(response)).contains(EmailTextAnalyzer.GIFT_CARD_PAYMENT, EmailTextAnalyzer.URGENCY_OR_THREAT);
	}

	@Test
	void urgencyAloneIsInconclusive() {
		EmailAnalysisResponse response = EmailTextAnalyzer.analyze(
				"Final notice. Your package will be returned within 24 hours unless you respond.");

		assertThat(response.assessment()).isEqualTo(EmailAssessment.inconclusive);
		assertThat(ruleIds(response)).containsExactly(EmailTextAnalyzer.URGENCY_OR_THREAT);
		assertThat(response.findings().get(0).explanation()).contains("not treated as suspicion");
	}

	@Test
	void legitimateSecurityAdviceIsNotSuspicious() {
		EmailAnalysisResponse response = EmailTextAnalyzer.analyze("""
				We will never ask for your password.
				Do not buy gift cards because a caller demands payment.
				Store recovery codes in a password manager and turn on multi-factor authentication.
				""");

		assertThat(response.assessment()).isEqualTo(EmailAssessment.no_obvious_warning_signs);
		assertThat(ruleIds(response)).contains(EmailTextAnalyzer.NEGATED_SECRET_REQUEST);
		assertThat(ruleIds(response)).doesNotContain(
				EmailTextAnalyzer.CREDENTIAL_REQUEST,
				EmailTextAnalyzer.GIFT_CARD_PAYMENT,
				EmailTextAnalyzer.URGENCY_OR_THREAT);
	}

	@Test
	void negatedPasswordRequestIsNotACredentialRequest() {
		EmailAnalysisResponse response = EmailTextAnalyzer.analyze("Never share your password.");

		assertThat(response.assessment()).isEqualTo(EmailAssessment.no_obvious_warning_signs);
		assertThat(ruleIds(response)).containsExactly(EmailTextAnalyzer.NEGATED_SECRET_REQUEST);
	}

	@Test
	void messageWithNoWarningSignsHasNoFindings() {
		EmailAnalysisResponse response = EmailTextAnalyzer.analyze(
				"Hi Sam, the Tuesday status meeting is moved to 3pm. Please bring the printed agenda.");

		assertThat(response.assessment()).isEqualTo(EmailAssessment.no_obvious_warning_signs);
		assertThat(response.findings()).isEmpty();
	}

	@Test
	void negationDoesNotSuppressASeparateVerificationCodeRequest() {
		assertSuspiciousCredentialRequest("Never share your password, and enter the verification code now.");
		assertSuspiciousCredentialRequest("Never share your password. Enter the verification code now.");
	}

	@Test
	void legitimateSecurityWordingIsNotACredentialRequest() {
		assertNoCredentialOrGiftCard("Give each employee a password manager.");
		assertNoCredentialOrGiftCard("Tell users to choose a strong password.");
		assertNoCredentialOrGiftCard("Review the enterprise password policy.");
		assertNoCredentialOrGiftCard("We shared the password vault guide.");
		assertNoCredentialOrGiftCard("Please enter the lobby. Password resets are handled by IT.");
		assertNoCredentialOrGiftCard("Please enter the lobby and pin the notice.");
		assertNoCredentialOrGiftCard("Please confirm you received this note. Never share your password.");
		assertNoCredentialOrGiftCard("Submit the form after you change your password.");
	}

	@Test
	void giftCardMentionsAreNotPaymentRequests() {
		assertNoCredentialOrGiftCard("The sender included a gift card.");
		assertNoCredentialOrGiftCard("I received a gift card for my birthday. The code is on the receipt.");
		assertNoCredentialOrGiftCard("The gift card number is printed on the back.");
		assertNoCredentialOrGiftCard("Our gift card policy lists the cost center numbers.");
		assertNoCredentialOrGiftCard("Thanks for the gift card.");
		assertNoCredentialOrGiftCard("We sent a gift card to the team.");
	}

	@Test
	void urgencyWordingAloneStaysInconclusive() {
		assertInconclusive("Please update the calendar immediately.");
		assertInconclusive("Never share your password. Act now.");
	}

	@Test
	void requestAndResponseToStringOmitSubmittedContent() {
		String text = "Reply with your password. UNIQUE-TEXT-MARKER";
		EmailExtractRequest request = new EmailExtractRequest(text);
		EmailAnalysisResponse response = EmailTextAnalyzer.analyze(text);

		assertThat(request.toString()).doesNotContain("UNIQUE-TEXT-MARKER").doesNotContain("password");
		assertThat(response.toString()).doesNotContain("UNIQUE-TEXT-MARKER").doesNotContain("password");
		assertThat(response.assessment()).isEqualTo(EmailAssessment.suspicious);
	}

	@Test
	void everyResultIncludesLimitationsAndNoProbability() {
		EmailAnalysisResponse response = EmailTextAnalyzer.analyze("Hello from the facilities team.");

		assertThat(response.limitations()).containsExactly(
				EmailTextAnalyzer.MISSED_THREATS_LIMITATION,
				EmailTextAnalyzer.SCOPE_LIMITATION);
		assertThat(response.toString()).doesNotContain("Hello");
	}

	private static void assertSuspiciousCredentialRequest(String text) {
		EmailAnalysisResponse response = EmailTextAnalyzer.analyze(text);
		assertThat(response.assessment()).as(text).isEqualTo(EmailAssessment.suspicious);
		assertThat(ruleIds(response)).as(text).contains(EmailTextAnalyzer.CREDENTIAL_REQUEST);
	}

	private static void assertNoCredentialOrGiftCard(String text) {
		EmailAnalysisResponse response = EmailTextAnalyzer.analyze(text);
		assertThat(response.assessment()).as(text).isNotEqualTo(EmailAssessment.suspicious);
		assertThat(ruleIds(response)).as(text).doesNotContain(
				EmailTextAnalyzer.CREDENTIAL_REQUEST,
				EmailTextAnalyzer.GIFT_CARD_PAYMENT);
	}

	private static void assertInconclusive(String text) {
		EmailAnalysisResponse response = EmailTextAnalyzer.analyze(text);
		assertThat(response.assessment()).as(text).isEqualTo(EmailAssessment.inconclusive);
		assertThat(ruleIds(response)).as(text).contains(EmailTextAnalyzer.URGENCY_OR_THREAT);
		assertThat(ruleIds(response)).as(text).doesNotContain(
				EmailTextAnalyzer.CREDENTIAL_REQUEST,
				EmailTextAnalyzer.GIFT_CARD_PAYMENT);
	}

	private static List<String> ruleIds(EmailAnalysisResponse response) {
		return response.findings().stream().map(EmailFinding::ruleId).toList();
	}

}
