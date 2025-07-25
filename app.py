import os
import json
import hmac
import hashlib
from flask import Flask, request, abort
from dotenv import load_dotenv
import discord
from discord.ext import commands
import asyncio
import threading
import time
import base64

load_dotenv()

# --- Configuration from .env ---
DISCORD_BOT_TOKEN = os.getenv('DISCORD_BOT_TOKEN')
SHOPIFY_WEBHOOK_SECRET = os.getenv('SHOPIFY_WEBHOOK_SECRET')
SHOPIFY_STORE_DOMAIN = os.getenv('SHOPIFY_STORE_DOMAIN')

# --- Flask App (for Webhook Listener) ---
app = Flask(__name__)

# Data storage for monitored collections and their roles/channels
MONITORED_COLLECTIONS = {}
PREVIOUS_INVENTORIES = {}

# Function to load data from JSON file
def load_data():
    global MONITORED_COLLECTIONS, PREVIOUS_INVENTORIES
    try:
        with open('monitored_data.json', 'r') as f:
            data = json.load(f)
            MONITORED_COLLECTIONS = data.get("monitored_collections", {})
            PREVIOUS_INVENTORIES = data.get("previous_inventories", {})
            print("Loaded existing monitoring data.")
    except FileNotFoundError:
        print("monitored_data.json not found, starting with empty data.")
        MONITORED_COLLECTIONS = {}
        PREVIOUS_INVENTORIES = {}
    except json.JSONDecodeError:
        print("Error reading monitored_data.json (likely empty or corrupted), starting with empty data.")
        MONITORED_COLLECTIONS = {}
        PREVIOUS_INVENTORIES = {}

# Save data to JSON file
def save_data():
    try:
        with open('monitored_data.json', 'w') as f:
            json.dump({
                "monitored_collections": MONITORED_COLLECTIONS,
                "previous_inventories": PREVIOUS_INVENTORIES
            }, f, indent=4)
        # print("Monitoring data saved.") # Uncomment for verbose saving logs
    except Exception as e:
        print(f"Error saving data: {e}")

# Load data when the app starts
load_data()


# Helper to verify Shopify webhook signature
def verify_shopify_webhook(data, hmac_header):
    if not SHOPIFY_WEBHOOK_SECRET or SHOPIFY_WEBHOOK_SECRET == 'YOUR_SHOPIFY_WEBHOOK_SECRET_HERE':
        print("Shopify webhook secret not set in .env or is default. Skipping verification (DANGEROUS!).")
        return True

    # --- DEBUG PRINTS ---
    print(f"DEBUG: Raw Data received (first 100 chars): {data[:100]}")
    print(f"DEBUG: Raw HMAC Header received: {hmac_header}")
    print(f"DEBUG: Secret from ENV: {SHOPIFY_WEBHOOK_SECRET}")

    secret_bytes = SHOPIFY_WEBHOOK_SECRET.encode('utf-8')
    print(f"DEBUG: Secret as bytes (first 10): {secret_bytes[:10]}")

    data_bytes = data
    if isinstance(data, str):
        data_bytes = data.encode('utf-8')
    print(f"DEBUG: Data as bytes (first 100): {data_bytes[:100]}")

    calculated_hmac_bytes = hmac.new(secret_bytes, data_bytes, hashlib.sha256).digest()
    generated_digest_base64 = base64.b64encode(calculated_hmac_bytes).decode('utf-8')

    print(f"DEBUG: Generated Digest (Base64): {generated_digest_base64}")

    hmac_header_lower = hmac_header.lower()
    generated_digest_base64_lower = generated_digest_base64.lower()

    print(f"DEBUG: HMAC Header (lower): {hmac_header_lower}")
    print(f"DEBUG: Generated Digest (lower): {generated_digest_base64_lower}")

    comparison_result = hmac.compare_digest(generated_digest_base64_lower, hmac_header_lower)
    print(f"DEBUG: Comparison Result: {comparison_result}")
    # --- END DEBUG PRINTS ---

    return comparison_result


@app.route('/shopify_webhook', methods=['POST'])
def shopify_webhook():
    data = request.get_data()
    hmac_header = request.headers.get('X-Shopify-Hmac-Sha256')
    topic = request.headers.get('X-Shopify-Topic')
    product_id_from_header = request.headers.get('X-Shopify-Product-Id')

    print(f"Received webhook: Topic='{topic}', Product ID (from header)='{product_id_from_header}'")

    if not verify_shopify_webhook(data, hmac_header):
        print("Webhook verification failed!")
        abort(401)

    try:
        payload = json.loads(data)
    except json.JSONDecodeError:
        print("Failed to parse JSON payload.")
        abort(400)

    if topic == 'products/update':
        product_title = payload.get('title')
        product_handle = payload.get('handle')
        product_url = f"https://{SHOPIFY_STORE_DOMAIN}/products/{product_handle}"
        print(f"Processing products/update for product: '{product_title}' (ID: {payload.get('id')})")

        for variant in payload.get('variants', []):
            variant_id = str(variant.get('id'))
            current_quantity = variant.get('inventory_quantity', 0)
            previous_quantity = PREVIOUS_INVENTORIES.get(variant_id, 0)

            print(f"  Variant {variant_id} ('{variant.get('title')}'): Current Qty={current_quantity}, Previous Qty={previous_quantity}")

            if current_quantity > previous_quantity and current_quantity > 0:
                print(f"  --> Potential restock detected for variant {variant_id} of '{product_title}'.")

                matched_collection_name = None
                alert_details_for_product = None

                for coll_name, details in MONITORED_COLLECTIONS.items():
                    if coll_name.lower() in product_title.lower():
                        matched_collection_name = coll_name
                        alert_details_for_product = details
                        print(f"  Matched product '{product_title}' to monitored collection '{matched_collection_name}'.")
                        break

                if alert_details_for_product and discord_bot_running:
                    print(f"  Queueing alert for Discord bot for '{product_title}'.")
                    alert_queue.put_nowait({
                        'product_title': product_title,
                        'product_url': product_url,
                        'collection_name': matched_collection_name,
                        'discord_channel_id': alert_details_for_product.get('discord_channel_id'),
                        'role_id': alert_details_for_product.get('discord_role_id'),
                        'image_url': variant.get('featured_image', {}).get('src')
                    })
                elif not alert_details_for_product:
                    print(f"  Product '{product_title}' (variant {variant_id}) did not match any monitored collection by name. No alert sent.")
                else:
                    print(f"  Discord bot not running, could not queue alert for '{product_title}'.")

            PREVIOUS_INVENTORIES[variant_id] = current_quantity
            save_data()

    return 'OK', 200


# --- Discord Bot ---
intents = discord.Intents.default()
intents.message_content = True
intents.members = True

bot = commands.Bot(command_prefix='!', intents=intents)

alert_queue = asyncio.Queue()
discord_bot_running = False

@bot.event
async def on_ready():
    global discord_bot_running
    print(f'{bot.user.name} has connected to Discord!') # Using bot.user.name here
    discord_bot_running = True
    bot.loop.create_task(check_alerts_queue())

async def check_alerts_queue():
    while True:
        alert_data = await alert_queue.get()
        print(f"Processing alert from queue for: {alert_data['product_title']}")
        await send_restock_alert(
            alert_data['product_title'],
            alert_data['product_url'],
            alert_data['collection_name'],
            alert_data['discord_channel_id'],
            alert_data['role_id'],
            alert_data.get('image_url')
        )
        alert_queue.task_done()

@bot.command(name='add_monitor')
@commands.has_permissions(administrator=True)
async def add_monitor(ctx, collection_name: str, shopify_collection_id: int, role: discord.Role, channel: discord.TextChannel):
    MONITORED_COLLECTIONS[collection_name] = {
        "shopify_collection_id": shopify_collection_id,
        "discord_role_id": role.id,
        "discord_channel_id": channel.id
    }
    save_data()
    await ctx.send(f'Started monitoring collection "{collection_name}". Alerts will ping <@&{role.id}> in <#{channel.id}>.')
    print(f"Added monitor for {collection_name} (Shopify ID: {shopify_collection_id}) with role {role.id} in channel {channel.id}")

@bot.command(name='remove_monitor')
@commands.has_permissions(administrator=True)
async def remove_monitor(ctx, collection_name: str):
    if collection_name in MONITORED_COLLECTIONS:
        del MONITORED_COLLECTIONS[collection_name]
        save_data()
        await ctx.send(f'Stopped monitoring collection "{collection_name}".')
        print(f"Removed monitor for {collection_name}")
    else:
        await ctx.send(f'Collection "{collection_name}" is not currently being monitored.')

@bot.command(name='list_monitors')
async def list_monitors(ctx):
    if not MONITORED_COLLECTIONS:
        await ctx.send("No collections are currently being monitored.")
        return

    message = "Currently monitoring the following collections:\n"
    for name, details in MONITORED_COLLECTIONS.items():
        role_mention = f"<@&{details['discord_role_id']}>" if details.get('discord_role_id') else "No specific role"
        channel_mention = f"<#{details['discord_channel_id']}>" if details.get('discord_channel_id') else "No specific channel"
        message += f"- **{name}** (Shopify ID Placeholder: {details.get('shopify_collection_id')}) -> Pings {role_mention} in {channel_mention}\n"
    await ctx.send(message)

async def send_restock_alert(product_title, product_url, collection_name, discord_channel_id, role_id, image_url=None):
    channel = bot.get_channel(discord_channel_id)
    if not channel:
        print(f"Error: Discord channel with ID {discord_channel_id} not found for alert. Skipping.")
        return

    role_mention = f"<@&{role_id}>" if role_id else "@here"

    embed = discord.Embed(
        title=f"🚨 RESTOCK ALERT: {product_title}!",
        url=product_url,
        color=discord.Color.green()
    )
    embed.add_field(name="Collection", value=collection_name, inline=True)
    embed.add_field(name="Product Link", value=f"[Click Here!]({product_url})", inline=True)

    if image_url:
        embed.set_thumbnail(url=image_url)
    else:
        embed.set_thumbnail(url="https://cdn.shopify.com/s/files/1/0002/0698/3284/files/shopify-logo.png?v=1602375836")

    embed.set_footer(text=f"Detected: {time.strftime('%Y-%m-%d %H:%M:%S EDT', time.localtime())}")

    await channel.send(f"{role_mention} A product in **{collection_name}** has been restocked!", embed=embed)
    print(f"Discord alert sent for '{product_title}' to channel {channel.name}.")

# --- RUNNING DISCORD BOT IN A SEPARATE THREAD (CRITICAL CHANGE) ---

# This function will be executed in a new thread
def run_discord_bot_in_thread():
    try:
        print("Attempting to run Discord bot...")
        bot.run(DISCORD_BOT_TOKEN)
    except discord.LoginFailure:
        print("ERROR: Discord bot failed to log in. Check DISCORD_BOT_TOKEN. Is it correct and not expired?")
    except discord.HTTPException as e:
        print(f"ERROR: Discord bot HTTP Exception: {e} (Likely connection issue or API error)")
    except Exception as e:
        print(f"ERROR: An unexpected error occurred while running the Discord bot: {e}")
    finally:
        print("Discord bot thread finished.")

# A flag to ensure the thread is started only once when the module is imported by Gunicorn
_discord_thread_started = False

# This code runs when the 'app.py' module is imported by Gunicorn
if not _discord_thread_started:
    print("Initializing Discord bot thread...")
    discord_thread = threading.Thread(target=run_discord_bot_in_thread)
    discord_thread.daemon = True # Allows the main program to exit even if this thread is running
    discord_thread.start()
    _discord_thread_started = True
    print("Discord bot thread started in background.")

# IMPORTANT: Remove the old `if __name__ == '__main__':` block entirely.
# Gunicorn is responsible for running the Flask app directly.
# The threading for the Discord bot is now handled above.