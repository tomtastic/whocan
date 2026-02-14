# SSH Key Analyzer (Scala Version)

A Scala port of the Perl SSH key analyzer (whocan) that examines SSH public keys from authorized_keys files, extracts metadata, and validates key strength.

## Features

- **Analyzes SSH public keys** from authorized_keys files
- **Supports multiple key types**: RSA, DSS, ECDSA, ED25519
- **Calculates fingerprints**: MD5 and SHA256 (for SSHFP records)
- **Displays key strength**: Color-coded output based on modulus bits
- **Shows exponents**: Optional display of RSA key exponents
- **SSHFP format**: Can output DNS SSHFP resource record format
- **SSH-1 detection**: Identifies legacy SSH-1 keys (not decoded)

## Installation with mise

This project uses [mise](https://mise.jdx.dev/) for managing Java, Scala, and sbt versions. Here's how to get started:

### 1. Install mise

If you don't have mise installed yet:

```bash
# macOS/Linux
curl https://mise.run | sh

# Or via package manager
# macOS: brew install mise
# Ubuntu/Debian: apt install mise
```

Add mise to your shell (add this to your `~/.bashrc` or `~/.zshrc`):

```bash
eval "$(mise activate bash)"  # or zsh, fish, etc.
```

Restart your shell or source your rc file.

### 2. Install Project Tools

Navigate to the project directory and run:

```bash
cd /path/to/ssh-key-analyzer
mise install
```

This will automatically install:
- **Java (OpenJDK 21)** - Required for running Scala
- **Scala 3.3.1** - The Scala compiler
- **sbt 1.9.7** - Scala Build Tool

You can verify the installation:

```bash
mise list
java --version
scala --version
sbt --version
```

### 3. Build the Project

There are two ways to run the analyzer:

#### Option A: Using Scala Script (Quick)

```bash
scala-cli run SSHKeyAnalyzer.scala -- ~/.ssh/authorized_keys
```

This runs it directly without compilation. Good for quick testing.

#### Option B: Build JAR (Recommended for Production)

```bash
# Compile and create executable JAR (with sbt)
sbt assembly

# This creates: target/scala-3.3.1/ssh-key-analyzer.jar
```

```bash
# Compile and create executable JAR (with scala-cli)
scala-cli package SSHKeyAnalyzer.scala -o ssh-key-analyzer.jar

# This creates: ./ssh-key-analyzer.jar
```

## Usage

### Basic Usage

```bash
# Using script
scala-cli run SSHKeyAnalyzer.scala -- /path/to/authorized_keys

# Using JAR
java -jar target/scala-3.3.1/ssh-key-analyzer.jar /path/to/authorized_keys
```

### Command-line Options

```bash
-h, --help, -?       Show help message and version
-e, --exponent       Display RSA key exponents
-s, --sha, --sshfp   Show SHA256 fingerprint in SSHFP RR format
-d, --debug          Enable debug output
```

### Examples

**Analyze your authorized_keys file:**
```bash
scala-cli run SSHKeyAnalyzer.scala -- ~/.ssh/authorized_keys
```

**Show RSA exponents:**
```bash
scala-cli run SSHKeyAnalyzer.scala -- -e ~/.ssh/authorized_keys
```

**Generate SSHFP DNS records:**
```bash
scala-cli run SSHKeyAnalyzer.scala -- -s ~/.ssh/authorized_keys
```

**Debug mode:**
```bash
scala-cli run SSHKeyAnalyzer.scala -- -d ~/.ssh/authorized_keys
```

## Output Format

### Standard Output
```
Line  KeyType             Bits   Fingerprint (MD5)                                 Comment
---- ------------------- ------ ------------------------------------------------- -------------
1    ssh-rsa             2048   16:27:ac:a5:76:28:2d:36:63:1b:56:4d:eb:df:a6:48  "user@host"
```

### With Exponents (-e)
```
Line  KeyType             Bits   Exponent    Fingerprint (MD5)                                 Comment
---- ------------------- ------ ----------- ------------------------------------------------- -------------
1    ssh-rsa             2048   65537       16:27:ac:a5:76:28:2d:36:63:1b:56:4d:eb:df:a6:48  "user@host"
```

### SSHFP Format (-s)
```
Line  KeyType             Bits   "SSHFP RR record"                                    Comment
---- ------------------- ------ ---------------------------------------------------- -------------
1    ssh-rsa             2048   "SSHFP 1 2 ABC123...XYZ789"                          "user@host"
```

## Color Coding

Terminal output is color-coded based on key strength:

- 🟢 **Green**: Strong keys (≥4096 bits for RSA, or ECDSA/ED25519)
- 🟡 **Yellow**: Moderate keys (1024-2047 bits)
- 🔴 **Red**: Weak keys (<1024 bits for RSA)

## Key Type Support

| Key Type | Supported | Notes |
|----------|-----------|-------|
| ssh-rsa | ✅ | Shows modulus bits and exponent |
| ssh-dss | ✅ | Shows modulus bits |
| ecdsa-* | ✅ | Shows effective key size |
| ssh-ed25519 | ✅ | Shows key size |
| ssh-1 | ⚠️ | Detected but not fully decoded |

## Security Best Practices

Based on the output:

- **Avoid**: Keys with <2048 bits (RSA) or SSH-1 keys
- **Acceptable**: 2048-bit RSA keys for general use
- **Recommended**: 4096-bit RSA or ED25519 keys
- **Modern**: ED25519 keys (256-bit, equivalent to ~3000-bit RSA)

## Cybersecurity Use Cases

As a cybersecurity engineer, you can use this tool to:

1. **Audit authorized_keys files** across your infrastructure
2. **Identify weak keys** that need rotation
3. **Generate SSHFP records** for DNS-based SSH key verification
4. **Track key usage** by analyzing fingerprints
5. **Detect duplicate keys** across multiple servers
6. **Verify key strength** compliance with security policies

## Project Structure

```
.
├── .mise.toml              # mise tool version configuration
├── build.sbt               # sbt build configuration
├── project/
│   └── plugins.sbt         # sbt plugins (assembly)
├── SSHKeyAnalyzer.scala    # Main application source
└── README.md               # This file
```

## Differences from Perl Version

This Scala port maintains functional parity with the original Perl script:

- ✅ Same command-line interface
- ✅ Same output formats
- ✅ Same fingerprint calculations
- ✅ Color-coded terminal output
- ✅ SSHFP record generation
- ✅ All key types supported

Improvements:
- Type-safe implementation
- Better error handling
- More maintainable code structure
- Runs on JVM (cross-platform)

## Troubleshooting

### "could_not_decode" in output
The key is not a valid base64-encoded SSH public key. Check the file format.

### "not_implemented" for SSH-1 keys
SSH-1 keys are legacy and deprecated. Consider regenerating with SSH-2.

### mise tools not activating
Make sure mise is properly configured in your shell:
```bash
mise doctor
```

### sbt assembly fails
Ensure you have internet access for downloading dependencies:
```bash
mise install
sbt clean
sbt assembly
```

## Version History

- **0.65-scala** - Initial Scala port from Perl version 0.65
  - Full feature parity with original
  - Added mise-based tool management
  - Type-safe implementation

## Original Credits

Original Perl version by TRCM:
- 10/01/2011 - Original bash version
- 11/09/2014 - Migrated to Perl
- 18/02/2017 - Added RSA exponent extraction

Scala port: 2025

## License

This tool is provided as-is for security auditing and SSH key management purposes.
