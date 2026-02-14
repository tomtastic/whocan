#!/bin/bash
# Quick start script for SSH Key Analyzer

set -e

echo "🔧 SSH Key Analyzer - Quick Start"
echo "=================================="
echo ""

# Check if mise is installed
if ! command -v mise &> /dev/null; then
    echo "❌ mise is not installed!"
    echo ""
    echo "Please install mise first:"
    echo "  curl https://mise.run | sh"
    echo ""
    echo "Then add to your shell (~/.bashrc or ~/.zshrc):"
    echo "  eval \"\$(mise activate bash)\"  # or zsh, fish, etc."
    echo ""
    exit 1
fi

echo "✅ mise is installed"
echo ""

# Install tools
echo "📦 Installing Java, Scala, and sbt via mise..."
mise install

echo ""
echo "✅ Tools installed successfully!"
echo ""

# Verify installations
echo "📋 Installed versions:"
mise list
echo ""

# Test with sample file
echo "🧪 Testing with sample authorized_keys file..."
echo ""

if [ -f "sample_authorized_keys" ]; then
    scala-cli run SSHKeyAnalyzer.scala -- sample_authorized_keys
    echo ""
    echo "✅ Test successful!"
else
    echo "⚠️  sample_authorized_keys not found, skipping test"
fi

echo ""
echo "🎉 Setup complete!"
echo ""
echo "Usage examples:"
echo "  scala-cli run SSHKeyAnalyzer.scala -- ~/.ssh/authorized_keys"
echo "  scala-cli run SSHKeyAnalyzer.scala -- -e ~/.ssh/authorized_keys"
echo "  scala-cli run SSHKeyAnalyzer.scala -- -s ~/.ssh/authorized_keys"
echo ""
echo "To build a JAR:"
echo "  sbt assembly"
echo "  java -jar target/scala-3.3.1/ssh-key-analyzer.jar <file>"
echo ""
