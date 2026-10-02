# 📖 Tutorial: How to set up your Discord bot

This guide will help you create a bot on the Discord platform, obtain its access Token, and secure it properly on your computer before running the code.

---

## Step 1: Creating the application on the Discord Developer Portal

To get started, we need to tell Discord that we want to create a new bot.

1. Go to the [Discord Developer Portal](https://discord.com/developers/applications) and log in with your Discord account.
2. In the top right corner, click the **New Application** button.
3. Choose a name for your bot and click **Create**.

> <img width="1905" height="292" alt="image" src="https://github.com/user-attachments/assets/b64793f3-41a3-4fc2-9a38-b8b7ee54311f" />

> `![Creating the application]'

---

## Step 2: Getting the Token and setting permissions

The Token is your bot's password. Anyone with this token can control your bot, so you must keep it secret!

1. In the left menu, navigate to the **Bot** section.
2. Under the bot's name, click the **Reset Token** button (or *Copy* if it is already visible).
3. Copy the long string of characters and paste it into a Notepad for now. 

> <img width="1906" height="794" alt="image" src="https://github.com/user-attachments/assets/ae0b4bca-fcbc-4bb4-9415-21e18bd2fe1e" />

> `![Getting the Token](image_name_2.png)`

4. **VERY IMPORTANT:** Scroll down on the same page to the **Privileged Gateway Intents** section and check **Message Content Intent**. Without this option, the bot will not be able to read your chat commands! Click **Save Changes**.

---

## Step 3: Securing the Token in the `.env` file

Never write the Token directly in your Python code (`bot.py`), especially if you plan to upload the code to GitHub. We will hide it in a separate configuration file.

1. Open your project folder.
2. Create a new file and name it exactly **`.env`** (make sure it starts with a dot).
3. Open the `.env` file and write the following line, pasting the token you copied in Step 2:

```env
DISCORD_TOKEN=paste_your_token_here_without_quotes
