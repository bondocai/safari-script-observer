// Known-bad file fingerprints, reported to the model as evidence. Each entry matches the SHA-256 of the first
// `prefixBytes` bytes of a file, so the extension never contains the bytes.
const signatures = [
  {
    name: "EICAR-Test-File",
    prefixBytes: 68,
    // The EICAR file may be followed by whitespace, up to 128 bytes in total.
    maxBytes: 128,
    sha256: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
  }
];

// Files larger than this are not scanned; the model is told the file was not scanned.
const maxScanBytes = 20 * 1024 * 1024;
