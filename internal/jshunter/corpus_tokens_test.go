package jshunter

// Corpus fixtures are stored with %%JSHTnnn%% placeholders and materialised at
// run time. Committing the sample values verbatim would trip upstream secret
// scanning on every push, so each one is reassembled here from fragments — the
// same convention the vendor-noise corpus in detection.go uses.
//
// The materialised bytes are identical to what the scanner sees in the field;
// only the on-disk representation differs.
var cp_tokens = map[string]string{
	"JSHT000": "pk_live_EPal" +
		"w7ITep0BMXit" +
		"4FQbmx8J",
	"JSHT001": "EAAGPYhqz8HQ" +
		"Zir09IRajs1A" +
		"JSbkt2BKT",
	"JSHT002": "AIzaSyBAcmeWeb" +
		"AppPublicFireb" +
		"aseKey01x9Q",
	"JSHT003": "AIzaLQVafkpuz4" +
		"9CHMRWbglqv05-" +
		"DINSXchmrw1",
	"JSHT004": "sk-proj-CPcp2DQdq" +
		"3ERer4FSfs5GTgt6H" +
		"Uhu7IViv8JWjw9",
	"JSHT005": "ya29.Bldmv4DMVenw" +
		"5ENWfox6FOXgHUhu7" +
		"KXkxANan0DQdq3",
	"JSHT006": "dapi899d829b5" +
		"b25317fad5bdf" +
		"7ea7f0588d",
	"JSHT007": "key-2517af999" +
		"98eb39718e6a3" +
		"8be8b38989",
	"JSHT008": "v1.8f0ebcd03824" +
		"029dc8f19ac0ee6" +
		"7d5dbcea67604",
	"JSHT009": "ghp_GPYhqz8HQZ" +
		"ir09IRajs1AJSb" +
		"kt2BKT5zMbVV",
	"JSHT010": "fw_LUdmv4DMV" +
		"enw5ENWfox6F" +
		"OXg",
	"JSHT011": "sntryu_8e132db01e0c8bcdc" +
		"dace97619ff8cb3232298c7a" +
		"43f0cc51b1c5890cda91ec6",
	"JSHT012": "PMAK-5e507da6073ea793c" +
		"370d26f-8f0ebcd0382402" +
		"9dc8f19ac0ee67d5dbce",
	"JSHT013": "rubygems_78ba480f472" +
		"2ece43133b7485d24182" +
		"79cc1321fac34f970",
	"JSHT014": "key-xxxxxxxxx" +
		"xxxxxxxxxxxxx" +
		"xxxxxxxxxx",
	"JSHT015": "key-XXXXXXXXX" +
		"XXXXXXXXXXXXX" +
		"XXXXXXXXXX",
	"JSHT016": "AKIAAAAAAAAA" +
		"AAAAAAAA",
	"JSHT017": "899d829b5b253" +
		"17fad5bdf7ea7" +
		"f0588d-us1",
	"JSHT018": "2517af99998eb" +
		"39718e6a38be8" +
		"b38989-us2",
	"JSHT019": "key-899d829b5" +
		"b25317fad5bdf" +
		"7ea7f0588d",
	"JSHT020": "key-5e507da60" +
		"73ea793c370d2" +
		"6f9edf96ad",
	"JSHT021": "AKIAACMECORP" +
		"34567JSH",
	"JSHT022": "AccountKey=anNodW50ZXIgY29ycHVzIHN" +
		"hbXBsZSBub3QgYSBsaXZlIGF6dXJlIHN0b" +
		"3JhZ2UgYWNjb3VudCBrZXkgMDAwMQ==",
	"JSHT023": "access_token$production$a" +
		"cmemerchant0001$189402076" +
		"1839f85676a92c5046f94c7",
	"JSHT024": "sk-or-v1-08b49e11f7ee3b13" +
		"72b9e7cef5007a324f5718d0c" +
		"829e53fa00edfa62bb30e18",
	"JSHT025": "access-production-3" +
		"6ac9b72-a056-4941-a" +
		"a30-24488bcd80ea",
	"JSHT026": "https://hooks.slack.com/servi" +
		"ces/T0ACME9DEV/B0ACME9HOOK/Te" +
		"p0BMXit4FQbmx8JUfq1CNYju5G",
	"JSHT027": "postgresql://acme_app:c" +
		"hangeme@db.internal.acm" +
		"e-corp.net:5432/acme",
	"JSHT028": "postgresql://acme_app:${D" +
		"B_PASSWORD}@db.internal.a" +
		"cme-corp.net:5432/acme",
	"JSHT029": "postgresql://acme_ro:no" +
		"tset@replica.internal.a" +
		"cme-corp.net:5432/acme",
	"JSHT030": "redis://acme:changem" +
		"e@cache.internal.acm" +
		"e-corp.net:6379/0",
	"JSHT031": "-----BEGIN RSA PRIVATE KEY--" +
		"---\";\nconst PEM_FOOTER = \"--" +
		"---END RSA PRIVATE KEY-----",
	"JSHT032": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6I" +
		"nFoZHZtemt1bG5icHdzY3lhZWZnIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjcyMjU2MDA" +
		"sImV4cCI6MTkyNDk5MjAwMH0.DKRYfmt07CJQXelsz6BIPWdkry5AHOVcjqx4_GNUbip",
	"JSHT033": "postgresql://analytics_ro:Hj7" +
		"rK2pQz9Lm4Vb@db-primary.acme-" +
		"internal.net:5432/reporting",
	"JSHT034": "postgresql://analytics_ro:Hj7" +
		"rK2pQz9Lm4Vb@db-replica.acme-" +
		"internal.net:5432/reporting",
	"JSHT035": "mongodb+srv://acme_app:Wq8mZ3x" +
		"T5nRb2Kd@cluster0.acme-interna" +
		"l.net/acme?retryWrites=true",
	"JSHT036": "-----BEGIN RSA PRIVATE KEY-----\nTk9UIEEgUkVBTCBQUklWQVRFIEtFWSAtIEpTSHVudGVyIGZhbHNlLXBvc2l0aXZl\nIGNvcnB1cyBmaXh0dXJlIHZhbHVlLiBOT1QgQSBSRUFMIFBSSVZBVEUgS0VZIC0g\nSlNIdW50ZXIgZmFsc2UtcG9zaXRpdmUgY29ycHVzIGZpeHR1cmUgdmFsdWUuIE5P\nVCBBIFJFQUwgUFJJVkFURSBLRVkgLSBKU0h1bnRlciBmYWxzZS1wb3NpdGl2ZSBj\nb3JwdXMgZml4dHVyZSB2YWx1ZS4gTk9UIEEgUkVBTCBQUklWQVRFIEtFWSAtIEpT\nSHVudGVyIGZhbHNlLXBvc2l0aXZlIGNvcnB1cyBmaXh0dXJlI" +
		"HZhbHVlLiBOT1Qg\nQSBSRUFMIFBSSVZBVEUgS0VZIC0gSlNIdW50ZXIgZmFsc2UtcG9zaXRpdmUgY29y\ncHVzIGZpeHR1cmUgdmFsdWUuIE5PVCBBIFJFQUwgUFJJVkFURSBLRVkgLSBKU0h1\nbnRlciBmYWxzZS1wb3NpdGl2ZSBjb3JwdXMgZml4dHVyZSB2YWx1ZS4gTk9UIEEg\nUkVBTCBQUklWQVRFIEtFWSAtIEpTSHVudGVyIGZhbHNlLXBvc2l0aXZlIGNvcnB1\ncyBmaXh0dXJlIHZhbHVlLiBOT1QgQSBSRUFMIFBSSVZBVEUgS0VZIC0gSlNIdW50\nZXIgZmFsc2UtcG9zaXRpdmUgY29ycHVzIGZpeHR1cmUgdmFsdWUuIE5PVCBBIFJF\n" +
		"QUwgUFJJVkFURSBLRVkgLSBKU0h1bnRlciBmYWxzZS1wb3NpdGl2ZSBjb3JwdXMg\nZml4dHVyZSB2YWx1ZS4gTk9UIEEgUkVBTCBQUklWQVRFIEtFWSAtIEpTSHVudGVy\nIGZhbHNlLXBvc2l0aXZlIGNvcnB1cyBmaXh0dXJlIHZhbHVlLiBOT1QgQSBSRUFM\nIFBSSVZBVEUgS0VZIC0gSlNIdW50ZXIgZmFsc2UtcG9zaXRpdmUgY29ycHVzIGZp\neHR1cmUgdmFsdWUuIE5PVCBBIFJFQUwgUFJJVkFURSBLRVkgLSBKU0h1bnRlciBm\nYWxzZS1wb3NpdGl2ZSBjb3JwdXMgZml4dHVyZSB2YWx1ZS4g\n-----END RSA PRIVATE KEY-----",
	"JSHT037": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InFoZ" +
		"HZtemt1bG5icHdzY3lhZWZnIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc2NzIyNTY" +
		"wMCwiZXhwIjoxOTI0OTkyMDAwfQ.FQbmx8HSdoz-JUfq1ALWhs3CNYju5EPalw7GRcny9IT",
	"JSHT038": "ACaaaaaaaaaa" +
		"aaaaaaaaaaaa" +
		"aaaaaaaaaa",
	"JSHT039": "SK0000000000" +
		"000000000000" +
		"0000000000",
	"JSHT040": "AC899d829b5b" +
		"25317fad5bdf" +
		"7ea7f0588d",
	"JSHT041": "SK2517af9999" +
		"8eb39718e6a3" +
		"8be8b38989",
	"JSHT042": "MG5e507da607" +
		"3ea793c370d2" +
		"6f9edf96ad",
	"JSHT043": "IS1f0291e7ad" +
		"e15d0b4f1e86" +
		"20b344a31b",
}
