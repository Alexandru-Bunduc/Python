import discord
from discord.ext import commands
import random
import string


intents = discord.Intents.default()
intents.message_content = True


bot = commands.Bot(command_prefix='!', intents=intents)

@bot.event
async def on_ready():
    print(f'Bot successfully connected as {bot.user}')

#roll the dice
@bot.command(name='roll')
async def roll(ctx, sides: int = 6):
    """Rolls a dice with a specified number of sides (default 6)."""
    result = random.randint(1, sides)
    await ctx.send(f'🎲 You rolled: {result}')
#Random number between X and Y
@bot.command(name='number')
async def number(ctx, min_val: int, max_val: int):
    """Picks a random number between min_val and max_val."""
    if min_val > max_val:
        await ctx.send("The minimum value must be smaller than the maximum value.")
        return
    
    result = random.randint(min_val, max_val)
    await ctx.send(f'6️⃣7️⃣Random number: {result}')
#Picks an option
@bot.command(name='pick')
async def pick(ctx, *choices):
    """Picks a random item from the provided options."""
    if not choices:
        await ctx.send("❌ Please provide some options to pick from! (e.g., !pick yes no maybe)")
        return
    
    winner = random.choice(choices)
    await ctx.send(f'🎯 I picked: **{winner}**')

#Shuffles a list
@bot.command(name='shuffle')
async def shuffle(ctx, *items):
    """Randomizes the order of the provided items."""
    if len(items) < 2:
        await ctx.send("❌ Please provide at least two items to shuffle!")
        return
    
    items_list = list(items)
    random.shuffle(items_list)
    await ctx.send(f'🔀 Shuffled list: {", ".join(items_list)}')
#Generates a random text
@bot.command(name='string')
async def random_string(ctx, length: int = 8):
    """Generates a random string of letters and numbers."""
    if length > 2000: 
        await ctx.send("❌ Discord messages cannot exceed 2000 characters.")
        return
        
    characters = string.ascii_letters + string.digits
    result = ''.join(random.choices(characters, k=length))
    await ctx.send(f'🔠 Random string: `{result}`')


bot.run('k')