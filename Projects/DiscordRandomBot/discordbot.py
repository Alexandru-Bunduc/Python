import discord
from discord.ext import commands
import random


intents = discord.Intents.default()
intents.message_content = True


bot = commands.Bot(command_prefix='!', intents=intents)

@bot.event
async def on_ready():
    print(f'Bot successfully connected as {bot.user}')


@bot.command(name='roll')
async def roll(ctx, sides: int = 6):
    """Rolls a dice with a specified number of sides (default 6)."""
    result = random.randint(1, sides)
    await ctx.send(f'🎲 You rolled: {result}')

@bot.command(name='number')
async def number(ctx, min_val: int, max_val: int):
    """Picks a random number between min_val and max_val."""
    if min_val > max_val:
        await ctx.send("The minimum value must be smaller than the maximum value.")
        return
    
    result = random.randint(min_val, max_val)
    await ctx.send(f'6️⃣7️⃣Random number: {result}')


bot.run('k')