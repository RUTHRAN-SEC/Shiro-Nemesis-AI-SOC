# 02 - Put the project on GitHub

Do this on **one** laptop first (any). The other laptop will download ("clone") it.

## Step 1 - Create an empty repository on GitHub

1. Sign in at github.com.
2. Click **+** (top right) -> **New repository**.
3. Name: `shiro-nemesis-ai-soc`.
4. Choose **Private** (recommended while learning) or Public (portfolio).
5. Do **NOT** tick "Add a README", ".gitignore" or "license" (we already have them).
6. Click **Create repository**. Keep the page open - it shows your repository address.

## Step 2 - Prepare the project folder

Unzip the project, then open a terminal inside the folder `shiro-nemesis-ai-soc`.

Check Git knows who you are (one time only):

```bash
git config --global user.name  "Your Name"
git config --global user.email "you@example.com"
```

## Step 3 - First commit

```bash
git init
git branch -M main
git add .
git status          # check: you should NOT see ".env" or "data/" files listed
git commit -m "Initial commit: Shiro x Nemesis AI SOC lab"
```

> `.env` holds your secret token and API key. It is listed in `.gitignore`, so Git ignores it. Never remove that line.

## Step 4 - Push to GitHub

Replace `YOUR-USERNAME` with your GitHub name:

```bash
git remote add origin https://github.com/YOUR-USERNAME/shiro-nemesis-ai-soc.git
git push -u origin main
```

GitHub asks you to sign in. Use a **Personal Access Token** instead of a password
(GitHub -> Settings -> Developer settings -> Personal access tokens), or install the GitHub CLI (`gh auth login`).

## Step 5 - Check that tests run on GitHub

Open your repository -> **Actions** tab. The `tests` workflow should run and turn green after a minute.

## Step 6 - Download it on the other laptop

```bash
git clone https://github.com/YOUR-USERNAME/shiro-nemesis-ai-soc.git
```

## Daily workflow when you change something

```bash
git add .
git commit -m "Describe what you changed"
git push                 # on the laptop where you edited
git pull                 # on the other laptop to get the change
```

## Good habits

* Commit small changes with clear messages.
* Never commit `.env`, tokens or API keys. If you ever do, create a new token and API key right away.
* Both laptops run the **same repository**; each laptop just runs its own half (Ubuntu = Nemesis, Windows = Guardian).
