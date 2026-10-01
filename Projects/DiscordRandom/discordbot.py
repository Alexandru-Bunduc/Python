import discord
from discord.ext import commands
import random
import string
import os
from dotenv import load_dotenv

load_dotenv()
TOKEN = os.getenv('DISCORD_TOKEN')
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

@bot.command(name='setseed')
@commands.has_permissions(administrator=True)
async def set_seed(ctx, number: int):
    random.seed(number)
    await ctx.send(f"✅Seed number is {number}")

@bot.command(name='resetseed')
@commands.has_permissions(administrator=True)
async def reset_seed(ctx):
    random.seed(None)
    await ctx.send("🔄 Seed was reset to random.")


@bot.command(name='pickwinners')
@commands.has_permissions(administrator=True)
async def pick_winners(ctx, number_winners: int, *participants):
    if number_winners > len(participants):
        await ctx.send("🚨 Warning! There are more winners than participants.")
        return
    else:
        winners = random.sample(participants, number_winners)
        await ctx.send(f"🏆 The winners are: {', '.join(winners)}")

#error handler
@bot.event
async def on_command_error(ctx, error):
    #not an admin error
    if isinstance(error, commands.MissingPermissions):
        await ctx.send("⛔ You don't have Administrator permissions to use this command!")
        
    #wrong param error
    elif isinstance(error, commands.MissingRequiredArgument):
        await ctx.send(f"❓ You are missing a required argument: `{error.param.name}`. Please check the command and try again.")
        
    #wrong argument
    elif isinstance(error, commands.BadArgument):
        await ctx.send("🔢 Invalid argument! Please make sure you are using numbers where expected.")
        
    #ignores fake commans
    elif isinstance(error, commands.CommandNotFound):
        pass
        
    #other
    else:
        print(f"An unexpected error occurred: {error}")
bot.run(TOKEN)