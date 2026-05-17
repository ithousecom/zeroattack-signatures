// ioc_obf_comments_1_text — ithouse override of defended.net's
// ioc_php_obf_comments_1.
//
// The upstream rule is a raw byte pattern with no binary-file guard,
// so it false-positives on bundled font / image assets (mPDF, dompdf
// and tcpdf all ship .ttf fonts). The upstream rule is disabled in
// cfg/actions.toml; this replacement keeps the same detection for
// TEXT / code files — PHP, JavaScript, HTML, CSS — because the same
// /* */ comment-obfuscation technique is used by JS malware too, and
// only skips binary assets.

rule ioc_obf_comments_1_text {
  meta:
    author      = "ithouse — override of defended.net ioc_php_obf_comments_1"
    description = "comment-obfuscation in text/code files (PHP, JS, HTML); binary assets excluded"
    license     = "https://creativecommons.org/licenses/by-nc-sa/4.0"

  strings:
    // Same pattern as upstream ioc_php_obf_comments_1:
    // <newline> . <0-10 spaces> //|/*
    $h1 = { (0D 0A | 0A) 2E 20[0-10] (2F 2F | 2F 2A) }

  condition:
    $h1 and
    // Skip binary assets — a font or image is not code in any
    // language. Every text file (PHP, JS, HTML, CSS) passes this
    // guard, so JS/PHP malware using the same obfuscation is caught.
    not (
      uint32be(0) == 0x00010000 or  // TTF
      uint32be(0) == 0x4f54544f or  // OTF   (OTTO)
      uint32be(0) == 0x74746366 or  // TTC   (ttcf)
      uint32be(0) == 0x774f4646 or  // WOFF
      uint32be(0) == 0x774f4632 or  // WOFF2
      uint32be(0) == 0x89504e47 or  // PNG
      uint16be(0) == 0xffd8     or  // JPEG
      uint32be(0) == 0x47494638     // GIF
    )
}
