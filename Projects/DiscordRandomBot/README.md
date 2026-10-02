# Randomizer - Custom Python Discord Bot

Randomizer is a custom Discord bot built in Python that handles essential randomization tasks. It allows users to safely generate random numbers, strings, and choices, offering advanced features like admin seed configuration for reproducible results and multiple winner selections. 

This project was developed in phases to demonstrate API interactions, error handling, and memory-safe random state manipulation.

## Features

* **Basic Randomization:** Generate random strings, numbers, or roll dice with specific constraints.
* **List Shuffling:** Traverse and shuffle provided lists of items directly in the chat.
* **Admin Seed Control:** Set or reset the random seed for reproducible results, ensuring transparency in giveaways.
* **Winner Picker:** Randomly pick multiple unique winners from a provided list without repetition.
* **Global Error Handling:** Built-in safeguards prevent the bot from crashing, providing clear feedback on missing arguments or lack of permissions.

## Prerequisites

* Python 3.x
* External libraries required: `discord.py` and `python-dotenv`.

## Usage

Invite the bot to your server, open any text channel, and use the following syntax:

`!<command> [arguments...]`

## Examples

1. Roll a 6-sided dice: `!roll 6`
2. Pick a random number between 1 and 100: `!number 1 100`
3. Pick a random choice from a list: `!pick yes no maybe`
4. Set the random seed for reproducible results (Admin only): `!setseed 1234`
5. Pick 2 unique winners from a list (Admin only): `!pickwinners 2 Alex Dan Stefan Matei`

> 💡 **New to Discord bots?** Check out my step-by-step [Visual Setup Tutorial](TUTORIAL.md) to learn how to create your bot, get your token, and safely set up your `.env` file.
