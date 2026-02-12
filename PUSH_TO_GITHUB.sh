#!/bin/bash
# Script to push sqlmap enhancements to GitHub
# Run this after creating a new GitHub repository

echo "=========================================="
echo "GitHub Repository Setup"
echo "=========================================="
echo ""
echo "Choose authentication method:"
echo "1) Personal Access Token (HTTPS) - Recommended"
echo "2) SSH (if you have SSH keys set up)"
echo ""
read -p "Enter choice (1 or 2): " AUTH_METHOD

if [ "$AUTH_METHOD" = "1" ]; then
    echo ""
    echo "Enter your GitHub repository URL (e.g., https://github.com/YOUR_USERNAME/YOUR_REPO.git):"
    read GITHUB_REPO
    
    if [ -z "$GITHUB_REPO" ]; then
        echo "Error: Repository URL is required"
        exit 1
    fi
    
    echo ""
    echo "You'll need a Personal Access Token (PAT) with 'repo' scope."
    echo "Create one at: https://github.com/settings/tokens"
    echo ""
    echo "When prompted for password, paste your PAT instead."
    echo ""
    read -p "Press Enter to continue..."
    
    # Extract username from URL for credential helper
    USERNAME=$(echo "$GITHUB_REPO" | sed -n 's|https://github.com/\([^/]*\)/.*|\1|p')
    
    # Add the new remote (remove old one if it exists)
    git remote remove upstream 2>/dev/null || true
    git remote add upstream "$GITHUB_REPO"
    
    # Push using token authentication
    echo ""
    echo "Pushing to GitHub..."
    echo "Username: $USERNAME"
    echo "Password: (paste your Personal Access Token)"
    git push -u upstream master
    
elif [ "$AUTH_METHOD" = "2" ]; then
    echo ""
    echo "Enter your GitHub repository SSH URL (e.g., git@github.com:YOUR_USERNAME/YOUR_REPO.git):"
    read GITHUB_REPO
    
    if [ -z "$GITHUB_REPO" ]; then
        echo "Error: Repository URL is required"
        exit 1
    fi
    
    # Add the new remote (remove old one if it exists)
    git remote remove upstream 2>/dev/null || true
    git remote add upstream "$GITHUB_REPO"
    
    # Push using SSH
    echo ""
    echo "Pushing to GitHub via SSH..."
    git push -u upstream master
    
else
    echo "Invalid choice. Exiting."
    exit 1
fi

echo ""
echo "✅ Successfully pushed to GitHub!"
echo "Your repository is now available at: $GITHUB_REPO"
