# GitHub Setup Guide

GitHub no longer accepts passwords for Git operations. You need to use either a **Personal Access Token (PAT)** or **SSH keys**.

## Option 1: Personal Access Token (Recommended - Easiest)

### Step 1: Create a Personal Access Token

1. Go to GitHub Settings → Developer settings → Personal access tokens → Tokens (classic)
   - Direct link: https://github.com/settings/tokens
2. Click **"Generate new token"** → **"Generate new token (classic)"**
3. Give it a name (e.g., "sqlmap-upload")
4. Select the **`repo`** scope (this gives full repository access)
5. Click **"Generate token"**
6. **Copy the token immediately** - you won't be able to see it again!

### Step 2: Create Your Repository

1. Go to https://github.com/new
2. Name your repository (e.g., `sqlmap-enhanced`)
3. Choose Public or Private
4. **Do NOT** check "Initialize with README" (we already have files)
5. Click **"Create repository"**

### Step 3: Push Your Code

Run the helper script:
```bash
cd /Users/patrickcrumbaugh/Downloads/sqlmap
./PUSH_TO_GITHUB.sh
```

When prompted:
- Choose option **1** (Personal Access Token)
- Enter your repository URL: `https://github.com/YOUR_USERNAME/YOUR_REPO.git`
- When asked for password, **paste your Personal Access Token** (not your GitHub password)

---

## Option 2: SSH Keys (If you already have them set up)

If you already have SSH keys configured with GitHub, you can use SSH URLs instead:

1. Create your repository on GitHub (same as Step 2 above)
2. Run the script and choose option **2** (SSH)
3. Enter your SSH URL: `git@github.com:YOUR_USERNAME/YOUR_REPO.git`

---

## Manual Commands (Alternative)

If you prefer to run commands manually:

### Using Personal Access Token:
```bash
cd /Users/patrickcrumbaugh/Downloads/sqlmap

# Add your repository (replace with your URL)
git remote add upstream https://github.com/YOUR_USERNAME/YOUR_REPO.git

# Push (when prompted for password, use your PAT)
git push -u upstream master
```

### Using SSH:
```bash
cd /Users/patrickcrumbaugh/Downloads/sqlmap

# Add your repository (replace with your SSH URL)
git remote add upstream git@github.com:YOUR_USERNAME/YOUR_REPO.git

# Push
git push -u upstream master
```

---

## Troubleshooting

**"Authentication failed"**
- Make sure you're using a Personal Access Token, not your password
- Verify the token has the `repo` scope enabled
- Check that the repository URL is correct

**"Permission denied (publickey)"** (SSH)
- Make sure your SSH key is added to GitHub: https://github.com/settings/keys
- Test your SSH connection: `ssh -T git@github.com`

**"Remote already exists"**
- Remove the old remote first: `git remote remove upstream`
- Then add it again with the correct URL
