#!/bin/bash

echo "=========================================="
echo "  Universal Hash Cracker - Installer"
echo "=========================================="
echo ""

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 not found!"
    echo "   Please install Python 3.6 or higher"
    exit 1
fi

echo "✓ Python3 found: $(python3 --version)"

# Create virtual environment
echo ""
echo "[1/5] Creating virtual environment..."
python3 -m venv venv

if [ ! -d "venv" ]; then
    echo "❌ Failed to create venv"
    exit 1
fi
echo "✓ Virtual environment created"

# Activate virtual environment
echo ""
echo "[2/5] Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo ""
echo "[3/5] Upgrading pip..."
pip install --upgrade pip --quiet
echo "✓ Pip upgraded"

# Install Python dependencies
echo ""
echo "[4/5] Installing Python dependencies..."
pip install bcrypt pyzipper --quiet
echo "✓ bcrypt installed"
echo "✓ pyzipper installed"

# Check for unrar (optional)
echo ""
echo "[5/5] Checking optional dependencies..."

if command -v unrar &> /dev/null; then
    echo "✓ unrar found: $(unrar --version | head -1)"
else
    echo "⚠️  unrar not found (optional for RAR support)"
    echo "   Install with: sudo apt-get install unrar"
fi

if command -v 7z &> /dev/null; then
    echo "✓ 7z found"
else
    echo "⚠️  7z not found (optional for archive support)"
    echo "   Install with: sudo apt-get install p7zip-full"
fi

# Create passwords.txt if not exists
if [ ! -f "passwords.txt" ]; then
    echo ""
    echo "📝 Creating default passwords.txt..."
    cat > passwords.txt << EOF
123456
password
123456789
qwerty
admin
12341234
password123
letmein
welcome
monkey
dragon
baseball
master
hello
freedom
whatever
EOF
    echo "✓ Created passwords.txt with 16 passwords"
fi

echo ""
echo "=========================================="
echo "  ✅ INSTALLATION COMPLETE!"
echo "=========================================="
echo ""
echo "  📁 Virtual environment: venv/"
echo "  📄 Wordlist: passwords.txt"
echo ""
echo "  🚀 TO RUN:"
echo "     source venv/bin/activate"
echo "     python hashbrute.py"
echo ""
echo "  🔚 TO DEACTIVATE:"
echo "     deactivate"
echo ""
echo "=========================================="