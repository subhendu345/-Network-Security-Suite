#!/bin/bash
echo "🛠️ Quick Fix All Issues"

# Fix permissions
find . -name "*.py" -exec chmod +x {} \;
find . -name "*.sh" -exec chmod +x {} \;

# Install dependencies
pip3 install -r requirements.txt

# Fix line endings
find . -name "*.sh" -exec dos2unix {} \;

echo "✅ Fixed all issues!"


---

## 📦 Requirements File

### `requirements.txt`
