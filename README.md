# SSH Key Analyzer (Scala Version)

A Scala port of the Perl SSH key analyzer [whocan](https://github.com/tomtastic/scripts/blob/master/whocan) that examines SSH public keys from authorized_keys files, extracts metadata, and validates key strength.

```shell
Line  KeyType             Bits   Exponent    Fingerprint (MD5)                                 Comment
---- ------------------- ------ ----------- ------------------------------------------------- -------------
3    ssh-rsa              2048   65537       9d:33:ff:be:8b:6d:11:38:77:42:9b:0e:0f:76:7a:bb   "user@example.com (2048-bit RSA)"
4    ssh-rsa              1024   65537       d3:27:34:4a:c7:ec:b7:3e:df:eb:0d:d7:31:bc:2f:be   "user@host (weak 1024-bit RSA)"
5    ssh-ed25519          248    n/a         65:96:2d:fc:e8:d5:a9:11:64:0c:0f:ea:00:6e:5b:bd   "user@modern.host (ED25519)"
6    ecdsa-sha2-nistp256  256    n/a         7b:99:81:1e:4c:91:a5:0d:5a:2e:2e:80:13:3f:24:ca   "user@ecdsa.host (ECDSA)"
```

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

## Key Type Support

| Key Type | Supported | Notes |
|----------|-----------|-------|
| ssh-rsa | ✅ | Shows modulus bits and exponent |
| ssh-dss | ✅ | Shows modulus bits |
| ecdsa-* | ✅ | Shows effective key size |
| ssh-ed25519 | ✅ | Shows key size |
| ssh-1 | ⚠️ | Detected but not fully decoded |


## Use Cases

You can use this tool to:

1. **Audit authorized_keys files** across your infrastructure
2. **Identify weak keys** that need rotation
3. **Generate SSHFP records** for DNS-based SSH key verification
4. **Track key usage** by analyzing fingerprints
5. **Detect duplicate keys** across multiple servers
6. **Verify key strength** compliance with security policies


## Differences from Perl Version

This Scala port maintains functional parity with the original Perl script, but also has :
- Type-safe implementation
- Better error handling
- More maintainable code structure
- Runs on JVM (cross-platform)


## Original Credits

- 10/01/2011 - Original bash version (trcm)
- 11/09/2014 - Migrated to Perl (trcm) 
- 18/02/2017 - Added RSA exponent extraction (trcm)

## License

This tool is provided as-is for security auditing and SSH key management purposes.
