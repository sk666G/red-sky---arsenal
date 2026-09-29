package recon2

import (
	"strings"
	"testing"
)

// A realistic forged email — From shows example.com but Return-Path says
// attacker.evil, SPF fails, no DKIM/DMARC results, Message-ID doesn't
// match the From domain.
const forgedEmail = `From: "PayPal Support" <security@example.com>
Return-Path: <bounce@attacker.evil>
Reply-To: <reply@attacker.evil>
To: victim@target.com
Subject: Your account has been limited
Date: Tue, 15 Sep 2026 12:00:00 +0000
Message-ID: <12345@attacker.evil>
Received-SPF: fail (domain of example.com does not designate 1.2.3.4 as permitted sender)
Received: from mail.attacker.evil (mail.attacker.evil [1.2.3.4])
	by mx.target.com with ESMTP id abc123
	for <victim@target.com>; Tue, 15 Sep 2026 12:00:01 +0000

Body goes here.
`

func TestMailTraceFromHeuristics(t *testing.T) {
	tr, err := ReadMailBytes([]byte(forgedEmail))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(tr.From, "example.com") {
		t.Fatalf("From parse: %q", tr.From)
	}
	if !strings.Contains(tr.ReturnPath, "attacker.evil") {
		t.Fatalf("ReturnPath parse: %q", tr.ReturnPath)
	}
	if tr.Subject != "Your account has been limited" {
		t.Fatalf("Subject: %q", tr.Subject)
	}
	if !strings.Contains(tr.MessageID, "attacker.evil") {
		t.Fatalf("MessageID: %q", tr.MessageID)
	}
}

func TestMailTraceReceivedChain(t *testing.T) {
	tr, err := ReadMailBytes([]byte(forgedEmail))
	if err != nil {
		t.Fatal(err)
	}
	if len(tr.Received) != 1 {
		t.Fatalf("want 1 hop, got %d", len(tr.Received))
	}
	h := tr.Received[0]
	if h.From != "mail.attacker.evil" {
		t.Fatalf("hop.From = %q", h.From)
	}
	if h.IP != "1.2.3.4" {
		t.Fatalf("hop.IP = %q", h.IP)
	}
}

func TestMailTraceSuspectsMismatch(t *testing.T) {
	tr, err := ReadMailBytes([]byte(forgedEmail))
	if err != nil {
		t.Fatal(err)
	}
	// should flag From vs Return-Path domain mismatch
	found := false
	for _, s := range tr.Suspect {
		if strings.Contains(s, "Return-Path domain") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("no Return-Path mismatch flag in %v", tr.Suspect)
	}
	// should flag From vs Reply-To
	found = false
	for _, s := range tr.Suspect {
		if strings.Contains(s, "Reply-To domain") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("no Reply-To mismatch flag in %v", tr.Suspect)
	}
	// should flag SPF failure
	found = false
	for _, s := range tr.Suspect {
		if strings.Contains(s, "SPF") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("no SPF failure flag in %v", tr.Suspect)
	}
}

func TestMailTraceCleanEmail(t *testing.T) {
	clean := `From: alice@example.com
Return-Path: <alice@example.com>
To: bob@target.com
Subject: Lunch
Date: Tue, 15 Sep 2026 12:00:00 +0000
Message-ID: <abc@example.com>
Authentication-Results: mx.target.com; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass

Body.
`
	tr, err := ReadMailBytes([]byte(clean))
	if err != nil {
		t.Fatal(err)
	}
	// no mismatch should fire
	for _, s := range tr.Suspect {
		if strings.Contains(s, "Return-Path domain") || strings.Contains(s, "Reply-To domain") {
			t.Fatalf("clean email flagged: %q", s)
		}
	}
}

func TestMailTraceOriginIP(t *testing.T) {
	// two hops — the oldest one (last in the file) has the origin IP
	multi := `From: x@example.com
Received: from mx2.example.com ([5.5.5.5])
	by mx3.target.com
Received: from client.example.com ([1.1.1.1])
	by mx2.example.com

Body.
`
	tr, err := ReadMailBytes([]byte(multi))
	if err != nil {
		t.Fatal(err)
	}
	if len(tr.Received) != 2 {
		t.Fatalf("want 2 hops, got %d", len(tr.Received))
	}
	if tr.OriginIP != "1.1.1.1" {
		t.Fatalf("OriginIP = %q, want 1.1.1.1", tr.OriginIP)
	}
}

func TestMailTraceHeaderFolding(t *testing.T) {
	// folded header (continuation line)
	folded := `From: alice@example.com
Subject: This is a long subject that has been
	folded across multiple lines
	for readability

Body.
`
	tr, err := ReadMailBytes([]byte(folded))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(tr.Subject, "folded") || !strings.Contains(tr.Subject, "readability") {
		t.Fatalf("folded subject not joined: %q", tr.Subject)
	}
}

func TestMailTraceNoReceived(t *testing.T) {
	noRecv := `From: attacker@example.com
To: victim@target.com
Subject: Hello

Body.
`
	tr, err := ReadMailBytes([]byte(noRecv))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range tr.Suspect {
		if strings.Contains(s, "no Received") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("no Received-header flag fired: %v", tr.Suspect)
	}
}

func TestMailTraceFutureDate(t *testing.T) {
	future := `From: x@example.com
Date: Tue, 15 Sep 2099 12:00:00 +0000
Message-ID: <a@example.com>
Received: from mail.example.com ([1.1.1.1]) by mx.target.com

Body.
`
	tr, err := ReadMailBytes([]byte(future))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range tr.Suspect {
		if strings.Contains(s, "future") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("future date not flagged: %v", tr.Suspect)
	}
}

func TestMailTraceMessageIDMismatch(t *testing.T) {
	mm := `From: alice@example.com
Message-ID: <abc@otherdomain.com>
Received: from mail.example.com ([1.1.1.1]) by mx.target.com

Body.
`
	tr, err := ReadMailBytes([]byte(mm))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range tr.Suspect {
		if strings.Contains(s, "Message-ID") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("Message-ID mismatch not flagged: %v", tr.Suspect)
	}
}

func TestMailTraceAddressExtraction(t *testing.T) {
	// display name + angle-bracket address
	got := extractAddr(`"PayPal Support" <security@example.com>`)
	if got != "security@example.com" {
		t.Fatalf("extractAddr display-name form: %q", got)
	}
	got = extractAddr("plain@example.com")
	if got != "plain@example.com" {
		t.Fatalf("extractAddr plain form: %q", got)
	}
}

func TestMailTraceDomainExtraction(t *testing.T) {
	if domOf("user@example.com") != "example.com" {
		t.Fatalf("domOf simple: %q", domOf("user@example.com"))
	}
	if domOf("no-at-sign") != "" {
		t.Fatalf("domOf no-at: %q", domOf("no-at-sign"))
	}
	if domOf("user@sub.example.com") != "sub.example.com" {
		t.Fatalf("domOf subdomain: %q", domOf("user@sub.example.com"))
	}
}

func TestMailTraceDateParsing(t *testing.T) {
	formats := []string{
		"Tue, 15 Sep 2026 12:00:00 +0000",
		"15 Sep 2026 12:00:00 +0000",
		"Tue, 15 Sep 2026 12:00:00 GMT",
	}
	for _, f := range formats {
		if _, err := parseMailDate(f); err != nil {
			t.Fatalf("parseMailDate(%q) failed: %v", f, err)
		}
	}
}
