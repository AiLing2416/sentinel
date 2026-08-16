#!/bin/bash
# Sentinel Automatic Hot-patching Script

# Try user installation first
FLATPAK_BASE=~/.local/share/flatpak/app/io.github.ailing2416.sentinel/x86_64/master
if [ ! -d "$FLATPAK_BASE" ]; then
    # Fallback to system installation
    FLATPAK_BASE=/var/lib/flatpak/app/io.github.ailing2416.sentinel/x86_64/master
fi
DEPLOY="active"
if [ ! -d "$FLATPAK_BASE/$DEPLOY/files" ]; then
    DEPLOY=$(ls "$FLATPAK_BASE" | grep -E '^[0-9a-f]{64}$' | sort | tail -1)
fi
SITE="$FLATPAK_BASE/$DEPLOY/files/lib/python3.13/site-packages/sentinel"

echo "Updating Sentinel components to: $SITE"

# Copy modified files
mkdir -p "$SITE/views" "$SITE/services" "$SITE/utils" "$SITE/db" "$SITE/models" "$SITE/vault"
cp src/application.py "$SITE/application.py"
cp src/views/*.py "$SITE/views/"
cp src/services/*.py "$SITE/services/"
cp src/utils/*.py "$SITE/utils/"
cp src/db/*.py "$SITE/db/"
cp src/models/*.py "$SITE/models/"
cp src/vault/*.py "$SITE/vault/"

# Clean up pyc files
find "$SITE" -name "*.pyc" -delete

# Compile and copy translation files (.po → .mo) into Flatpak share dir
echo "🌐 Compiling and updating translations in Flatpak..."
FLATPAK_LOCALE="$FLATPAK_BASE/$DEPLOY/files/share/sentinel/locale"
for lang in en zh_CN zh_TW de; do
    if [ -f "po/${lang}.po" ]; then
        mkdir -p "$FLATPAK_LOCALE/${lang}/LC_MESSAGES"
        msgfmt "po/${lang}.po" -o "$FLATPAK_LOCALE/${lang}/LC_MESSAGES/sentinel.mo"
    fi
done

echo "Hot-patch complete! You can run flatpak run io.github.ailing2416.sentinel now."
