from flask import Flask, render_template, request, session, redirect, url_for, flash, jsonify, get_flashed_messages, flash, Response
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, HiddenField
from wtforms.validators import DataRequired
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from pymongo import MongoClient
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
import os, requests
import re
import time
from bson import ObjectId
from flask_wtf.csrf import CSRFProtect, CSRFError
from shop_data import SHOP_ITEMS
from markupsafe import escape
import csv
from io import StringIO
from markupsafe import Markup
from pytz import timezone as pytz_timezone
from functools import lru_cache
import httpx
import nest_asyncio
nest_asyncio.apply()
import aiohttp
import asyncio
import traceback
from livereload import Server
import logging
import redis
from limits.storage import RedisStorage
import logging
load_dotenv()
import flask_limiter
print("[DEBUG] Flask-Limiter version:", flask_limiter.__version__)


app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "changeme")

app.config["RATELIMIT_STORAGE_URL"] = os.environ["REDIS_URL"]
app.config["RATELIMIT_DEFAULTS"] = ["50 per minute"]

limiter = Limiter(
    key_func=get_remote_address
)
limiter.init_app(app)

# Discord
DISCORD_CLIENT_ID = os.getenv("DISCORD_CLIENT_ID")
DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET")
DISCORD_REDIRECT_URI = os.getenv("DISCORD_REDIRECT_URI")
BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN")

STAFF_ROLES = {
    1018204467524546591: "Owner",
    1307838468788846652: "Co-Owner",
    1228215782312509531: "Head Admin",
    1086135543110303794: "Moderator",
    1086135499787345920: "Trial Moderator",
    1234364432252145674: "Verifier",
    1251737546770088028: "Giveaway Staff",
}


# CSRF protection
csrf = CSRFProtect(app)

# Session lifetime
app.permanent_session_lifetime = timedelta(days=7)

GUILD_ID = 959220051427340379  # your server ID
UNVERIFIED_ROLE_ID = 959238651999567893
MEMBER_ROLE_ID = 959220051469279296

COPENHAGEN_TZ = pytz_timezone("Europe/Copenhagen")


STAFF_ROLE_IDS = {"1307838468788846652"}
ROLE_ID_TO_NAME = {
    "123456789012345678": "Admin",
    "234567890123456789": "Moderator",
    "345678901234567890": "Booster",
    # Add your role ID to name mappings here
}

def parse_duration(duration_str):
    time_map = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    match = re.match(r"(\d+)([smhd])", duration_str.strip().lower())
    if match:
        num, unit = match.groups()
        return int(num) * time_map[unit]
    return 600  # fallback: 10m

def is_staff():
    return session.get("staff_role") is not None

def is_admin():
    return session.get("staff_role") in ["Owner", "Co-Owner", "Head Admin"]


def get_mongo_client():
    mongo_uri = os.getenv("MONGO_URI")
    return MongoClient(mongo_uri)

def serialize_auction(auction):
    auction["_id"] = str(auction["_id"])
    auction["end_time"] = auction.get("end_time").isoformat() if auction.get("end_time") else None

    # Pick fields to expose safely
    return {
        "id": auction["_id"],
        "item": auction.get("item", "Unknown"),
        "quantity": auction.get("quantity", 1),
        "current_bid": auction.get("current_bid", 0),
        "highest_bidder": auction.get("highest_bidder"),  # user ID
        "display_name": None,  # to fill below
        "bidder_tag": None,
        "end_time": auction["end_time"],
    }

def fetch_role_mapping(guild_id):
    url = f"https://discord.com/api/guilds/{guild_id}/roles"
    headers = {
        "Authorization": f"Bot {BOT_TOKEN}"
    }

    response = requests.get(url, headers=headers)
    response.raise_for_status()

    roles = response.json()

    # Create a dict with role ID mapped to name, color, position
    return {
        role["id"]: {
            "name": role["name"],
            "color": f"#{int(role['color']):06x}" if role["color"] != 0 else "#888",
            "position": role["position"]
        }
        for role in roles
    }

def calculate_achievements(xp, message_count, coins, streak, auctions_won=0, top_bidder_count=0, mentions=0):
    achievements = []

    # 📬 Message Milestones
    if message_count >= 10:
        achievements.append({"label": "💬 10 Messages", "tooltip": "Send 10 messages in the server"})
    if message_count >= 100:
        achievements.append({"label": "💬 100 Messages", "tooltip": "Send 100 messages in the server"})
    if message_count >= 500:
        achievements.append({"label": "💬 500 Messages", "tooltip": "Send 500 messages in the server"})
    if message_count >= 1_000:
        achievements.append({"label": "💬 1,000 Messages", "tooltip": "Send 1,000 messages in the server"})
    if message_count >= 5_000:
        achievements.append({"label": "💬 5,000 Messages", "tooltip": "Send 5,000 messages in the server"})
    if message_count >= 10_000:
        achievements.append({"label": "💬 10,000 Messages", "tooltip": "Send 10,000 messages in the server"})
    if message_count >= 25_000:
        achievements.append({"label": "💬 25,000 Messages", "tooltip": "Send 25,000 messages in the server"})
    if message_count >= 50_000:
        achievements.append({"label": "💬 50,000 Messages", "tooltip": "Send 50,000 messages in the server"})
    if message_count >= 100_000:
        achievements.append({"label": "💬 100,000 Messages", "tooltip": "Send 100,000 messages in the server"})

    # 💰 Coin Achievements
    if coins >= 100:
        achievements.append({"label": "🟡 First 100 Coins", "tooltip": "Earn 100 coins"})
    if coins >= 1_000:
        achievements.append({"label": "🟡 Coin Collector", "tooltip": "Earn 1,000 coins"})
    if coins >= 10_000:
        achievements.append({"label": "💸 Rolling in Coins (10k+)", "tooltip": "Earn 10,000 coins"})
    if coins >= 50_000:
        achievements.append({"label": "💰 Treasure Stacker (50k+)", "tooltip": "Earn 50,000 coins"})
    if coins >= 100_000:
        achievements.append({"label": "🤑 Rich Farmer (100k+)", "tooltip": "Earn 100,000 coins"})
    if coins >= 250_000:
        achievements.append({"label": "🏦 Vault Builder (250k+)", "tooltip": "Earn 250,000 coins"})
    if coins >= 500_000:
        achievements.append({"label": "💶 Coin Tycoon (500k+)", "tooltip": "Earn 500,000 coins"})
    if coins >= 1_000_000:
        achievements.append({"label": "👑 Millionaire Status", "tooltip": "Earn 1,000,000 coins"})

    # 🔥 Streaks
    if streak >= 2:
        achievements.append({"label": "🔥 Daily Habit (2+ days)", "tooltip": "Log in 2 days in a row"})
    if streak >= 5:
        achievements.append({"label": "🔥🔥 Consistent Farmer (5+ days)", "tooltip": "Log in 5 days in a row"})
    if streak >= 7:
        achievements.append({"label": "📅 Weekly Warrior (7+ days)", "tooltip": "Maintain a 7-day login streak"})
    if streak >= 14:
        achievements.append({"label": "🌾 Biweekly Beast (14+ days)", "tooltip": "Maintain a 14-day login streak"})
    if streak >= 30:
        achievements.append({"label": "🎯 1 Month Grind!", "tooltip": "Maintain a 30-day login streak"})
    if streak >= 60:
        achievements.append({"label": "🏆 2 Months Streak", "tooltip": "Maintain a 60-day login streak"})
    if streak >= 90:
        achievements.append({"label": "👑 Daily Legend (90+ days)", "tooltip": "Maintain a 90-day login streak"})

    # 🏅 Auctions
    if auctions_won >= 1:
        achievements.append({"label": "🏅 Auction Winner", "tooltip": "Win at least 1 auction"})
    if top_bidder_count >= 5:
        achievements.append({"label": "🎯 Top Bidder", "tooltip": "Be top bidder in 5+ auctions"})

    # 🤝 Trades (Mentions)
    if mentions >= 15:
        achievements.append({"label": "🔴 15+ safe trades!", "tooltip": "Complete 15 valid trades"})
    if mentions >= 30:
        achievements.append({"label": "🔴 30+ safe trades!", "tooltip": "Complete 30 valid trades"})
    if mentions >= 50:
        achievements.append({"label": "🔴 50+ Professional Trader", "tooltip": "Complete 50 valid trades"})
    if mentions >= 100:
        achievements.append({"label": "🟠 Master Of Trades 100+", "tooltip": "Complete 100 valid trades"})
    if mentions >= 200:
        achievements.append({"label": "🟠 Trade-a-saurus rex 200+", "tooltip": "Complete 200 valid trades"})
    if mentions >= 300:
        achievements.append({"label": "🟡 Bullish Banana 300+", "tooltip": "Complete 300 valid trades"})
    if mentions >= 400:
        achievements.append({"label": "🟡 Stocky McTradeface 400+", "tooltip": "Complete 400 valid trades"})
    if mentions >= 500:
        achievements.append({"label": "🟢 Profit Piranha 500+", "tooltip": "Complete 500 valid trades"})
    if mentions >= 600:
        achievements.append({"label": "🟢 Deal-a-whale 600+", "tooltip": "Complete 600 valid trades"})
    if mentions >= 700:
        achievements.append({"label": "🟢 Chart Chimp 700+", "tooltip": "Complete 700 valid trades"})
    if mentions >= 800:
        achievements.append({"label": "🔵 Market Munchkin 800+", "tooltip": "Complete 800 valid trades"})
    if mentions >= 900:
        achievements.append({"label": "🔵 Penny Pincher 900+", "tooltip": "Complete 900 valid trades"})
    if mentions >= 1000:
        achievements.append({"label": "🛡️ 1k Trades??? ur crazy", "tooltip": "Complete 1,000 valid trades"})

    return achievements


@app.errorhandler(429)
def ratelimit_handler(e):
    user_ip = request.remote_addr
    now = datetime.utcnow().isoformat()

    log_message = f"[RateLimit] {now} - Too many requests from {user_ip} on {request.path}"

    print(log_message)  # log to Fly logs

    # OPTIONAL: Save to MongoDB
    with MongoClient(os.getenv("MONGO_URI")) as client:
        client["Website"]["Logs"].insert_one({
            "type": "ratelimit",
            "ip": user_ip,
            "path": request.path,
            "timestamp": now
        })

    return jsonify({
        "error": "Too many requests, slow down.",
        "retry_after": e.description
    }), 429


@app.template_filter('format')
def format_number(n):
    return f"{n:,}" if isinstance(n, int) else n

@app.route("/shop", methods=["GET", "POST"])
def shop():
    discord_id = session.get("discord_id")
    coins = None
    owned_items = []

    if discord_id:
        with MongoClient(os.getenv("MONGO_URI")) as client:
            eco_user = client["Economy"]["Users"].find_one({"_id": int(discord_id)}) or {}
            coins = eco_user.get("coins", 0)
            owned_items = eco_user.get("owned_items", [])

    return render_template("shop.html", items=SHOP_ITEMS, coins=coins, owned_items=owned_items)


@app.route("/send-reply", methods=["POST"])
def send_reply():
    if not is_staff(session.get("roles", [])):
        return "Unauthorized", 403

    channel_id = request.form["channel_id"]
    message = request.form["message"]

    # Use requests.post to tell your bot server to send message
    requests.post("http://localhost:5000/api/send-message", json={
        "channel_id": channel_id,
        "message": message
    })
    return redirect("/active-tickets")


@app.route("/admin")
def admin_panel():
    if not is_staff():
        return "Unauthorized", 403

    role = session.get("staff_role")
    return render_template("admin.html", role=role)


@app.route("/remove-featured-achievement", methods=["POST"])
def remove_featured_achievement():
    if "discord_id" not in session:
        return redirect("/login")

    with MongoClient(os.getenv("MONGO_URI")) as client:
        users = client["Website"]["users"]
        users.update_one(
            {"_id": session["discord_id"]},
            {"$unset": {"featured_achievement": ""}}
        )

    return redirect("/profile")

@csrf.exempt
@app.route("/booster-dashboard", methods=["GET", "POST"])
def booster_dashboard():
    if not is_staff():
        return "❌ Access denied. You are not staff.", 403

    discord_id = int(session["discord_id"])
    message = None

    with MongoClient(os.getenv("MONGO_URI")) as client:
        booster_col = client["hayday"]["Booster"]
        user_col = client["Website"]["usernames"]
        roles_cache = client["Website"]["roles_cache"].find_one({"_id": "live"}) or {}

        # Handle form submission
        if request.method == "POST":
            target_id = int(request.form.get("target_id"))
            role_name = request.form.get("role_name")
            role_color = request.form.get("role_color")

            if not role_name or not role_color:
                message = "❌ Both fields are required."
            else:
                try:
                    r = requests.post(
                        os.getenv("BOT_WEBHOOK_URL") + "/webhook/booster-update",
                        json={
                            "discord_id": target_id,
                            "role_name": role_name,
                            "role_color": role_color
                        },
                        headers={"Authorization": os.getenv("BOT_WEBHOOK_KEY")}
                    )
                    message = "✅ Role updated!" if r.status_code == 200 else "❌ Failed to update role"
                except Exception as e:
                    message = f"❌ Error: {e}"

        # Load all boosters
        boosters = []
        all_boosters = list(booster_col.find({}))
        all_user_ids = [str(b["_id"]) for b in all_boosters]
        users = list(user_col.find({"_id": {"$in": all_user_ids}}))
        user_map = {u["_id"]: u for u in users}

        for b in all_boosters:
            user = user_map.get(str(b["_id"]))

            boosters.append({
                "user_id": str(b["_id"]),
                "display_name": user.get("display_name", "Unknown") if user else "Unknown",
                "username": user.get("username", "") if user else "",
                "avatar_url": user.get("avatar", "https://cdn.discordapp.com/embed/avatars/0.png") if user else "https://cdn.discordapp.com/embed/avatars/0.png",
                "role_name": b.get("role_name", "❓ Unknown"),
                "color": f"#{int(b.get('role_color', 0)):06x}"
            })

    return render_template("booster_dashboard.html", boosters=boosters, message=message)

@app.route("/force-logout", methods=["POST"])
def force_logout_all():
    if session.get("discord_id") != "154282062973501441":
        return "❌ Unauthorized", 403

    with MongoClient(os.getenv("MONGO_URI")) as client:
        # Clear all session data in the Website.users collection
        result = client["Website"]["users"].update_many({}, {
            "$unset": {
                "session": "",
                "last_login": "",
                "staff_role": "",
            }
        })

    # Optionally log out current user too
    session.clear()
    return redirect("/login")



@csrf.exempt
@app.route("/update-bio", methods=["POST"])
def update_bio():
    if "discord_id" not in session:
        return redirect(url_for("login"))

    new_bio = request.form.get("bio", "").strip()
    if len(new_bio) > 300:
        flash("❌ Bio must be under 300 characters.", "error")
        return redirect(url_for("profile"))

    safe_bio = escape(new_bio)  # prevent injection

    with MongoClient(os.getenv("MONGO_URI")) as client:
        users = client["Website"]["users"]
        users.update_one(
            {"_id": session["discord_id"]},
            {"$set": {"bio": safe_bio}}
        )

    flash("✅ Bio updated successfully!", "success")
    return redirect(url_for("profile"))


@csrf.exempt
@app.route("/set-featured-achievement", methods=["POST"])
def set_featured_achievement():
    if "discord_id" not in session:
        return jsonify({"success": False, "error": "Not logged in"}), 403

    new_badge = request.form.get("badge")
    if not new_badge:
        return jsonify({"success": False, "error": "Missing badge"}), 400

    with MongoClient(os.getenv("MONGO_URI")) as client:
        users = client["Website"]["users"]
        users.update_one(
            {"_id": session["discord_id"]},
            {"$set": {"featured_achievement": new_badge}}
        )

    return jsonify({"success": True})
    

@app.route("/api/button-toggles", methods=["GET", "POST"])
@csrf.exempt
def button_toggles():
    if not is_staff():
        return "Unauthorized", 403

    if "discord_id" not in session:
        return redirect("/login-page")

    with MongoClient(os.getenv("MONGO_URI")) as client:
        toggle_col = client["Website"]["ButtonToggles"]

        if request.method == "GET":
            toggles = {
                doc["_id"]: {
                    "enabled": doc["enabled"],
                    "reason": doc.get("reason", "")
                } for doc in toggle_col.find()
            }
            return jsonify(toggles)

        if request.method == "POST":
            data = request.json
            key = data.get("key")
            enabled = data.get("enabled", True)
            reason = data.get("reason", "").strip()

            if not enabled and not reason:
                reason = "🔒 This function is disabled by the staff."

            if key not in ["staff_application", "support", "giveaway", "verification", "auction"]:
                return jsonify({"error": "Invalid key"}), 400

            toggle_col.update_one(
                {"_id": key},
                {"$set": {"enabled": enabled, "reason": reason}},
                upsert=True
            )
            return jsonify({"message": f"{key} status updated."})



@app.route("/giveaways")
def giveaways_page():
    with MongoClient(os.getenv("MONGO_URI")) as client:
        db = client["Giveaway"]
        user_db = client["Website"]["usernames"]
        raw_giveaways = list(db["current_giveaways"].find({"ended": False}))

        # Step 1: Collect all unique user + host IDs
        user_ids = set()
        for g in raw_giveaways:
            user_ids.update(g.get("participants", {}).keys())
            if "host_id" in g:
                user_ids.add(str(g["host_id"]))

        # Load all relevant users
        users = user_db.find({"_id": {"$in": list(user_ids)}})
        user_map = {str(u["_id"]): u for u in users}

        giveaways = []
        now_ts = time.time()
        now = datetime.now(COPENHAGEN_TZ)
        guild_id = "959220051427340379"
        try:
            role_mapping = fetch_role_mapping(guild_id)
        except Exception as e:
            print(f"[Giveaways Page] Failed to fetch roles: {e}")
            role_mapping = {}

        for g in raw_giveaways:
            end = g.get("end_time")
            if not end:
                continue
            if end.tzinfo is None:
                end = end.replace(tzinfo=timezone.utc)
            end_local = end.astimezone(COPENHAGEN_TZ)

            # ✅ Skip expired
            if end_local.timestamp() < now_ts:
                continue

            # Time setup
            diff = int(end.timestamp() - now_ts)
            hours = diff // 3600
            minutes = (diff % 3600) // 60
            g["time_remaining"] = f"{hours}h {minutes}m"
            g["end_time"] = end_local
            g["end_time_str"] = f"<t:{int(end.timestamp())}:R>"
            g["end_time_ts"] = int(end.timestamp())

            # Giveaway info
            g["entry_count"] = sum(g.get("participants", {}).values())
            g["winners"] = g.get("winners_count", 1)
            g["guild_id"] = str(g.get("guild_id", GUILD_ID))
            g["channel_id"] = str(g.get("channel_id", ""))
            g["participants_percent"] = []
            g["participant_info"] = []

            required_id = str(g.get("required_role_id")) if g.get("required_role_id") else None
            g["required_role_name"] = role_mapping.get(required_id, {}).get("name") if required_id else None

            # Session roles
            user_roles = session.get("roles", [])
            bypass_role_id = "975188431636418681"
            g["has_bypass"] = bypass_role_id in user_roles
            g["can_join"] = not required_id or required_id in user_roles or g["has_bypass"]
            g["not_in_guild"] = str(MEMBER_ROLE_ID) not in user_roles

            # Host info
            host_id = str(g.get("host_id"))
            host = user_map.get(host_id)
            g["host_display"] = host.get("display_name", f"<@{host_id}>") if host else f"<@{host_id}>"
            g["host_avatar"] = (
                f"https://cdn.discordapp.com/avatars/{host_id}/{host.get('avatar_hash')}.png"
                if host and host.get("avatar_hash") else None
            )

            # Participants info
            total_entries = g["entry_count"]
            for uid, count in g.get("participants", {}).items():
                uid_str = str(uid)
                percent = round((count / total_entries) * 100, 2) if total_entries else 0
                user = user_map.get(uid_str)
                display_name = user.get("display_name", f"<@{uid_str}>") if user else f"<@{uid_str}>"
                avatar = (
                    f"https://cdn.discordapp.com/avatars/{uid_str}/{user.get('avatar_hash')}.png"
                    if user and user.get("avatar_hash") else None
                )

                g["participants_percent"].append({
                    "id": uid_str,
                    "count": count,
                    "percent": percent
                })
                g["participant_info"].append({
                    "id": uid_str,
                    "count": count,
                    "percent": percent,
                    "name": display_name,
                    "avatar": avatar
                })

            giveaways.append(g)

        return render_template(
            "giveaways.html",
            giveaways=giveaways,
            discord_id=session.get("discord_id"),
            user_roles=session.get("roles", []),
            year=now.year
        )

@app.route("/api/giveaways/won")
def won_giveaways():
    if "discord_id" not in session:
        return jsonify({"error": "Not logged in"}), 401

    page = int(request.args.get("page", 1))
    limit = 4
    skip = (page - 1) * limit
    discord_id = session["discord_id"]

    with MongoClient(os.getenv("MONGO_URI")) as client:
        col = client["Giveaway"]["current_giveaways"]

        query = {
            "ended": True,
            "winners": {"$in": [discord_id]}
        }

        total = col.count_documents(query)
        recent = list(col.find(query)
                      .sort("end_time", -1)
                      .skip(skip)
                      .limit(limit))

        usernames_col = client["Website"]["usernames"]

        for g in recent:
            g["_id"] = str(g["_id"])
            g["you_won"] = True

            # Timestamp fix
            end_time = g.get("end_time")
            if isinstance(end_time, datetime):
                g["end_time_ts"] = int(end_time.timestamp())
            else:
                g["end_time_ts"] = 0

            # Host display/avatars
            host_id = g.get("host_id")
            if host_id:
                profile = usernames_col.find_one({"_id": str(host_id)})
                g["host_display"] = profile.get("display_name", "Unknown") if profile else "Unknown"
                g["host_avatar"] = profile.get("avatar_url", "") if profile else ""

    return jsonify({
        "giveaways": recent,
        "page": page,
        "total": total,
        "limit": limit
    })





    
@app.route("/api/live-giveaways")
def api_live_giveaways():
    COPENHAGEN_TZ = pytz_timezone("Europe/Copenhagen")
    now_ts = time.time()

    with MongoClient(os.getenv("MONGO_URI")) as client:
        db = client["Giveaway"]
        user_db = client["Website"]["usernames"]
        raw_giveaways = list(db["current_giveaways"].find({"ended": False}))

        user_ids = set()
        for g in raw_giveaways:
            user_ids.update(g.get("participants", {}).keys())
            if "host_id" in g:
                user_ids.add(str(g["host_id"]))

        users = user_db.find({"_id": {"$in": list(user_ids)}})
        user_map = {str(u["_id"]): u for u in users}

        output = []

        for g in raw_giveaways:
            end = g.get("end_time")
            if not end:
                continue
            if end.tzinfo is None:
                end = end.replace(tzinfo=timezone.utc)
            end_ts = end.timestamp()
            if end_ts < now_ts:
                continue

            host_id = str(g.get("host_id"))
            host = user_map.get(host_id)

            output.append({
                "prize": g.get("prize"),
                "end_time_ts": int(end_ts),
                "host_display": host.get("username") if host else f"User {host_id}",
                "host_avatar": f"https://cdn.discordapp.com/avatars/{host_id}/{host.get('avatar_hash')}.png"
                    if host and host.get("avatar_hash") else None
            })

        return jsonify(output)


@app.route("/api/production-data")
def api_production_data():
    with MongoClient(os.getenv("MONGO_URI")) as client:
        col = client["hayday"]["ProductionGuide"]
        data = list(col.find({}, {"_id": 0}))  # Exclude _id for frontend use
    return jsonify(data)


@csrf.exempt
@app.route("/admin/production", methods=["GET", "POST"])
def admin_production():
    if not is_staff():
        return "Unauthorized", 403

    with MongoClient(os.getenv("MONGO_URI")) as client:
        col = client["hayday"]["ProductionGuide"]

        if request.method == "POST":
            if "delete_product" in request.form:
                to_delete = request.form.get("delete_product")
                col.delete_one({"product": to_delete})
            else:
                product = request.form.get("product").strip()
                machine = request.form.get("machine").strip()
                xp = int(request.form.get("xp"))
                price = int(request.form.get("price"))
                time_min = float(request.form.get("time_min"))
                level = int(request.form.get("level"))

                # Save image if uploaded
                image = request.files.get("image")
                if image and image.filename:
                    filename = product.lower().replace(" ", "_") + ".png"
                    image_path = os.path.join("static/img/hayday/products", filename)
                    image.save(image_path)
                    
                machine_image = request.files.get("machine_image")
                if machine_image and machine_image.filename:
                    filename = machine.lower().replace(" ", "_") + ".png"
                    image_path = os.path.join("static/img/hayday/machines", filename)
                    machine_image.save(image_path)

                col.update_one(
                    {"product": product},
                    {"$set": {
                        "machine": machine,
                        "xp": xp,
                        "price": price,
                        "time_min": time_min,
                        "level": level
                    }},
                    upsert=True
                )


            return redirect("/admin/production")


        all_items = list(col.find().sort("level", 1))

    return render_template("admin_production.html", products=all_items, year=datetime.now().year)




@app.route("/api/live-auctions")
def live_auctions():
    with MongoClient(os.getenv("MONGO_URI")) as client:
        db = client["hayday"]
        now = datetime.now(timezone.utc)
        auctions = list(db["auctions"].find({
            "status": "active",
            "end_time": {"$gt": now}
        }))
        user_cache = db["Website"]["UserCache"]

        results = []
        for auction in auctions:
            data = serialize_auction(auction)
            bidder_id = data.get("highest_bidder")
            if bidder_id:
                user_doc = user_cache.find_one({"user_id": bidder_id})
                if user_doc:
                    data["display_name"] = user_doc.get("display_name") or user_doc.get("username")
                    data["bidder_tag"] = user_doc.get("discord_tag")
            results.append(data)

    return jsonify(results)


@csrf.exempt
@app.route("/api/bid", methods=["POST"])
def api_bid():
    print("API BID endpoint called!")
    print("Request content-type:", request.content_type)
    print("Request data:", request.data)
    print("Request form:", request.form)
    print("Request args:", request.args)

    user_id = session.get("discord_id")
    if not user_id:
        return jsonify({"success": False, "message": "Not logged in via Discord"}), 401
    user_roles = session.get("roles", [])

    if not user_roles or str(UNVERIFIED_ROLE_ID) in user_roles:
        return jsonify({
            "success": False,
            "message": "❌ You must be a verified member of the Discord to bid. Join here: https://discord.gg/hayday"
        }), 403

    if str(MEMBER_ROLE_ID) not in user_roles:
        return jsonify({
            "success": False,
            "message": "❌ You must be a member of the Discord server to place bids. Join here: https://discord.gg/hayday"
        }), 403

    try:
        data = request.get_json(force=True)
        print("Received data from frontend:", data)
    except Exception as e:
        print("❌ JSON decode error:", e)
        return jsonify({"success": False, "message": "Invalid JSON"}), 400

    auction_id = data.get("auction_id")
    amount = data.get("amount")
    print(f"auction_id: {auction_id} (type: {type(auction_id)})")
    print(f"amount: {amount} (type: {type(amount)})")

    try:
        amount = int(amount)
        auction_id_int = int(auction_id)
    except (TypeError, ValueError):
        print("Failed to cast amount or auction_id to int!")
        return jsonify({"success": False, "message": "Invalid input (amount or auction_id)"}), 400

    print(f"🔍 Incoming bid: auction_id={auction_id_int}, amount={amount}, user_id={user_id}")

    if amount <= 0:
        print("amount <= 0")
        return jsonify({"success": False, "message": "Invalid input"}), 400

    with MongoClient(os.getenv("MONGO_URI")) as client:
        db = client["hayday"]
        auction = db["auctions"].find_one({"message_id": auction_id_int, "status": "active"})

        if not auction:
            print("Auction not found or already ended")
            return jsonify({"success": False, "message": "Auction not found or already ended"}), 404

        now = datetime.now(timezone.utc)
        end_time = auction["end_time"]
        if end_time.tzinfo is None:
            end_time = end_time.replace(tzinfo=timezone.utc)
        if end_time <= now:
            return jsonify({"success": False, "message": "Auction already expired"}), 410
        
        # Step 2: Bid validation
        current_bid = auction.get("current_bid", 0)
        min_increment = auction.get("min_increment") or 1
        if amount < current_bid + min_increment:
            print("Bid too low")
            return jsonify({
                "success": False,
                "message": f"Bid must be at least {min_increment:,} higher than the current bid."
            }), 400

        # Step 3: Update auction
        db["auctions"].update_one(
            {"_id": auction["_id"]},
            {"$set": {
                "current_bid": amount,
                "highest_bidder": int(user_id),
                "last_bid": {
                    "user_id": int(user_id),
                    "amount": amount,
                    "timestamp": datetime.utcnow()
                }
            },
            "$push": {
                "bid_logs": {
                    "user_id": int(user_id),
                    "amount": amount,
                    "timestamp": datetime.utcnow()
                }
            }}
        )

        try:
            requests.post(
                "https://discord-mega-bot.fly.dev/webhook/auction",
                json={
                    "message_id": auction_id_int,
                    "amount": amount,
                    "user_id": int(user_id),
                    "channel_id": auction["channel_id"]
                },
                headers={"Authorization": os.getenv("BOT_WEBHOOK_KEY")},
                timeout=3
            )
        except Exception as e:
            print(f"Failed to ping bot webhook: {e}")

    return jsonify({"success": True, "message": "Bid placed!"})


@app.route("/submit_bid", methods=["POST"])
def submit_bid():
    data = request.json
    message_id = int(data.get("message_id"))
    amount = int(data.get("amount"))
    user_id = int(session.get("discord_id"))

    if not user_id:
        return jsonify({"error": "Not authenticated"}), 403

    # Save bid in MongoDB
    with MongoClient(os.getenv("MONGO_URI")) as client:
        db = client["hayday"]
        auction = db["auctions"].find_one({"message_id": message_id, "status": "active"})
        if not auction:
            return jsonify({"error": "Auction not found or already ended"}), 404

        # Basic validation (same as bot)
        base_bid = auction["current_bid"] if auction["current_bid"] > 0 else auction["starting_bid"]
        min_inc = auction.get("min_increment", 1)
        if amount <= base_bid or (amount - base_bid) < min_inc:
            return jsonify({"error": "Invalid bid amount"}), 400

        db["auctions"].update_one(
            {"_id": auction["_id"]},
            {"$set": {
                "current_bid": amount,
                "highest_bidder": user_id,
                "last_bid": {
                    "user_id": user_id,
                    "amount": amount,
                    "timestamp": datetime.utcnow()
                }
            }}
        )

    # Optional: notify the bot via a webhook or a background task (ideal)
    try:
        requests.post(os.getenv("BOT_SYNC_URL"), json={
            "action": "refresh_auction",
            "message_id": message_id
        })
    except:
        pass

    return jsonify({"success": True})

@app.route("/auctions")
def auctions_page():
    with MongoClient(os.getenv("MONGO_URI")) as client:
        db = client["hayday"]
        auctions = list(db["auctions"].find({"status": "active"}).sort("end_time", 1))
        user_cache = list(client["Website"]["UserCache"].find())
        user_map = {str(u["_id"]): u for u in user_cache}

        # Ensure all owners are in the user_map
        owner_ids = {str(a['owner_id']) for a in auctions}
        # Optionally, fetch missing users and add to user_map if needed

    now = datetime.now(pytz_timezone("Europe/Copenhagen"))  # local time

    for auc in auctions:
        end = auc.get("end_time")
        if end:
            if end.tzinfo is None:
                end = end.replace(tzinfo=timezone.utc)
            end = end.astimezone(COPENHAGEN_TZ)
            auc["end_time"] = end  # update for HTML countdown
            auc["time_remaining"] = str(end - now).split(".")[0]
        else:
            auc["time_remaining"] = "Unknown"

        bidder_id = str(auc.get("highest_bidder"))
        user_info = user_map.get(bidder_id, {})
        auc["bidder_tag"] = user_info.get("tag") or f"User {bidder_id}"
        auc["display_name"] = user_info.get("display_name")
        auc["avatar"] = user_info.get("avatar")

        # Owner info for Jinja
        owner_id = str(auc.get("owner_id"))
        owner_info = user_map.get(owner_id, {})
        auc["owner_display_name"] = owner_info.get("display_name")
        auc["owner_tag"] = owner_info.get("tag")
        auc["owner_avatar"] = owner_info.get("avatar")

    discord_id = session.get("discord_id")
    return render_template("auctions.html", auctions=auctions, year=now.year, discord_id=discord_id)




@app.route("/current-bans")
def current_bans():
    search = request.args.get("search", "").lower()
    page = int(request.args.get("page", 1))
    per_page = 12

    with MongoClient(os.getenv("MONGO_URI")) as client:
        db = client["Moderation"]
        bans_cursor = db["ban_list"].find()
        bans = list(bans_cursor)

    print(f"[Ban Debug] Found {len(bans)} total bans from DB")

    if search:
        bans = [
            b for b in bans
            if search in b.get("name", "").lower() or search in b.get("reason", "").lower()
        ]

    print(f"[Ban Debug] Filtered to {len(bans)} after search")

    total = len(bans)
    start = (page - 1) * per_page
    end = start + per_page
    bans_paginated = bans[start:end]

    if request.args.get("ajax") == "1":
        return render_template(
            "partials/ban_cards.html",
            bans=bans_paginated,
            is_staff=is_staff(session.get("roles", []))  # ✅ fix here
        )


    return render_template(
        "current_bans.html",
        bans=bans_paginated,
        page=page,
        total_pages=(total + per_page - 1) // per_page,
        search=search,
        is_staff=is_staff  # ✅ this makes it available inside Jinja
    )

@app.route("/mod-action", methods=["POST"])
def mod_action():
    if "discord_id" not in session or not is_staff(session.get("roles", [])):
        return redirect(url_for("home"))

    user_input = request.form.get("user_input")
    action = request.form.get("action")
    duration_raw = request.form.get("duration", "")
    reason = request.form.get("reason", "No reason provided")

    try:
        target_user_id = str(user_input).strip("<@!>")
        target_user_id = int(target_user_id)

        with MongoClient(os.getenv("MONGO_URI")) as client:
            db = client["Moderation"]
            collection = db["mute"]
            now = int(time.time())

        if action == "mute":
            mute_end = now + parse_duration(duration_raw)
            result = collection.update_one(
                {"_id": str(target_user_id)},
                {
                    "$set": {
                        "end_time": mute_end,
                        "reason": reason,
                        "moderator": session["display_name"],
                        "moderator_id": session["discord_id"],
                        "muted": True
                    },
                    "$inc": {"mute_count": 1}
                },
                upsert=True
            )
            flash("✅ Mute added to the database.", "success")

        elif action == "unmute":
            result = collection.update_one(
                {"_id": str(target_user_id)},
                {
                    "$set": {"muted": False}
                }
            )
            flash("✅ Unmute request added to DB. Bot will process shortly.", "success")

        elif action in {"kick", "ban", "warn"}:
            action_doc = {
                "user_id": str(target_user_id),
                "action": action,
                "reason": reason,
                "timestamp": now,
                "moderator": session["display_name"],
                "moderator_id": session["discord_id"],
                "executed": False
            }
            db["web_actions"].insert_one(action_doc)
            flash(f"✅ {action.capitalize()} queued. Bot will process it shortly.", "success")

        elif action == "unban":
            db["web_actions"].insert_one({
                "user_id": str(target_user_id),
                "action": "unban",
                "reason": reason,
                "timestamp": now,
                "moderator": session["display_name"],
                "moderator_id": session["discord_id"],
                "executed": False
            })
            flash("✅ Unban request queued.", "success")

        else:
            flash("❌ Unknown action selected.", "error")

    except Exception as e:
        print(f"[mod_action] Error: {e}")
        flash("❌ Failed to perform action.", "error")

    return redirect("/staff-panel")


@app.route("/api/news")
def api_news():
    mongo_uri = os.getenv("MONGO_URI")
    with MongoClient(mongo_uri) as client:
        collection = client["hayday"]["NewsFeed"]
        items = list(collection.find().sort("_id", -1).limit(5))
        return jsonify([
            {
                "title": item.get("title", "Untitled"),
                "url": item.get("_id", "#"),
                "timestamp": item.get("timestamp") or datetime.utcnow().isoformat(),
                "source": item.get("source", "unknown"),
                "thumbnail": item.get("thumbnail")  # ✅ ensure this field is populated by your bot
            }
            for item in items
        ])





@app.route("/production_guide")
def production():
    return render_template("production_guide.html")

@app.route("/scam-ids")
def scam_ids():
    if not is_staff():
        return "Unauthorized", 403
    
    with MongoClient(os.getenv("MONGO_URI")) as client:
        collection = client["Scam"]["Banned"]

        # Collect all IDs
        all_ids = []
        for doc in collection.find():
            ids = doc.get("id", [])
            if isinstance(ids, list):
                all_ids.extend(ids)
            else:
                all_ids.append(ids)
        all_ids = sorted(set(all_ids), key=str.upper)
        # Pagination setup
        page = int(request.args.get("page", 1))
        per_page = 30
        total_pages = (len(all_ids) + per_page - 1) // per_page
        paginated_ids = all_ids[(page - 1) * per_page : page * per_page]
    
    return render_template(
        "scam_ids.html",
        scam_ids=paginated_ids,
        current_page=page,
        total_pages=total_pages,
        year=datetime.now().year
    )


@app.route("/")
def home():
    year = datetime.now(timezone.utc).year
    return render_template("index.html", year=year)

@app.route("/login-page")
def login_page():
    return render_template("login.html", sitekey=os.getenv("HCAPTCHA_SITEKEY"))

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    flash("⚠️ CAPTCHA must be completed before logging in.", "error")
    return redirect(url_for("login_page"))

@app.route("/verify-captcha", methods=["POST"])
def verify_captcha():
    if not request.form.get("agree_terms"):
        flash("❌ You must agree to the Terms of Service.", "error")
        return redirect(url_for("login_page"))

    token = request.form.get("h-captcha-response")
    if not token:
        flash("❌ CAPTCHA must be completed before logging in.", "error")
        return redirect(url_for("login_page"))

    verify = requests.post(
        "https://hcaptcha.com/siteverify",
        data={
            "response": token,
            "secret": os.getenv("HCAPTCHA_SECRET")
        }
    ).json()

    if verify.get("success"):
        return redirect(url_for("login"))  # Redirect to Discord OAuth
    else:
        flash("❌ CAPTCHA validation failed.", "error")
        return redirect(url_for("login_page"))

@app.route("/login")
def login():
    next_page = request.args.get("next", "/")
    session["next_page"] = next_page  # ✅ good
    return redirect(
        f"https://discord.com/oauth2/authorize?client_id={DISCORD_CLIENT_ID}"
        f"&redirect_uri={DISCORD_REDIRECT_URI}"
        f"&response_type=code"
        f"&scope=identify%20guilds.members.read"
        f"&guild_id=959220051427340379"
        f"&prompt=consent"
    )

@app.route("/admin/logs/export")
def export_logs():
    if not is_staff():
        return "Unauthorized", 403
    start_date_str = request.args.get("start_date")
    end_date_str = request.args.get("end_date")
    log_type = request.args.get("type")

    query = {"timestamp": {"$exists": True}}
    if log_type:
        query["type"] = log_type

    # Date filtering
    if start_date_str:
        query["timestamp"] = query.get("timestamp", {})
        query["timestamp"]["$gte"] = start_date_str  # "YYYY-MM-DD"

    if end_date_str:
        try:
            end_dt = datetime.strptime(end_date_str, "%Y-%m-%d") + timedelta(days=1)
            query["timestamp"]["$lt"] = end_dt.strftime("%Y-%m-%d")
        except ValueError:
            pass

    with MongoClient(os.getenv("MONGO_URI")) as client:
        logs = list(client["Website"]["Logs"].find(query).sort("timestamp", -1))

    # Build CSV
    si = StringIO()
    writer = csv.writer(si)
    writer.writerow(["Type", "Author", "Channel", "Timestamp", "Content", "Images"])

    for log in logs:
        images = ", ".join(log.get("images", [])) if "images" in log else ""
        if log["type"] == "message_edit":
            content = f"Before: {log.get('before', '')} | After: {log.get('after', '')}"
        else:
            content = log.get("content", "")
        writer.writerow([
            log.get("type"),
            log.get("author", {}).get("name", ""),
            log.get("channel_name", ""),
            log.get("timestamp", ""),
            content,
            images
        ])

    output = si.getvalue()
    si.close()

    filename = f"discord_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(output, mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment;filename={filename}"})

@csrf.exempt
@app.route("/admin/logs", methods=["GET", "POST"])
def view_logs():
    if not is_staff():
        return "Unauthorized", 403
    year = datetime.now(timezone.utc).year
    now = datetime.now(timezone.utc)

    search_term = request.form.get("search", "").strip() if request.method == "POST" else request.args.get("search", "").strip()
    selected_channel = request.form.get("channel_filter", "") if request.method == "POST" else request.args.get("channel_filter", "").strip()
    preset = request.args.get("preset", "").strip()

    deleted_page = int(request.args.get("deleted_page", 1))
    edited_page = int(request.args.get("edited_page", 1))
    per_page = 6  # 👈 adjust to how many logs per page you want

    query = {"timestamp": {"$exists": True}}

    if search_term:
        query["$or"] = [
            {"author.name": {"$regex": search_term, "$options": "i"}},
            {"author.id": search_term}
        ]

    if selected_channel:
        query["channel_name"] = selected_channel

    # ✅ Preset date filter logic
    if preset == "24h":
        query["timestamp"]["$gte"] = now - timedelta(hours=24)
    elif preset == "7d":
        query["timestamp"]["$gte"] = now - timedelta(days=7)
    elif preset == "this_week":
        start_of_week = now - timedelta(days=now.weekday())
        query["timestamp"]["$gte"] = datetime(start_of_week.year, start_of_week.month, start_of_week.day, tzinfo=timezone.utc)

    with MongoClient(os.getenv("MONGO_URI")) as client:
        logs_collection = client["Website"]["Logs"]
        all_logs = list(logs_collection.find(query).sort("timestamp", -1))

        deleted_logs = [log for log in all_logs if log.get("type") == "message_delete"]
        edited_logs = [log for log in all_logs if log.get("type") == "message_edit"]

        deleted_total = len(deleted_logs)
        edited_total = len(edited_logs)
        deleted_logs = deleted_logs[(deleted_page-1)*per_page : deleted_page*per_page]
        edited_logs = edited_logs[(edited_page-1)*per_page : edited_page*per_page]

        channels = logs_collection.distinct("channel_name", {"channel_name": {"$ne": None}})

    return render_template(
        "logs.html",
        deleted_logs=deleted_logs,
        edited_logs=edited_logs,
        deleted_page=deleted_page,
        deleted_total=deleted_total,
        edited_page=edited_page,
        edited_total=edited_total,
        per_page=per_page,
        search_term=search_term,
        selected_channel=selected_channel,
        preset=preset,
        channels=sorted(channels),
        year=year
    )


@app.route("/api/debug/session")
def debug_session():
    return jsonify({
        "has_roles": "roles" in session,
        "roles": session.get("roles"),
        "discord_id": session.get("discord_id")
    })

@app.route("/profile")
def profile():
    if "discord_id" not in session:
        return redirect(url_for("login"))

    discord_id = session["discord_id"]

    # Fetch role info
    guild_id = "959220051427340379"
    try:
        role_mapping = fetch_role_mapping(guild_id)
    except Exception as e:
        print("Failed to fetch roles:", e)
        role_mapping = {}

    user_roles = session.get("roles", [])
    enriched_roles = [
        {
            "id": rid,
            "name": role_mapping[rid]["name"],
            "color": role_mapping[rid]["color"],
            "position": role_mapping[rid]["position"]
        }
        for rid in user_roles if rid in role_mapping
    ]
    sorted_roles = sorted(enriched_roles, key=lambda r: r["position"], reverse=True)
    user_roles = session.get("roles", [])

    highest_role = sorted_roles[0] if sorted_roles else None

    # Fetch level data and calculate progress
    with MongoClient(os.getenv("MONGO_URI")) as client:
        level_col = client["hayday"]["level"]
        level_doc = level_col.find_one({"_id": discord_id})
        all_users = list(level_col.find().sort("xp", -1))  # used for rank
        users_collection = client["Website"]["users"]
        user = users_collection.find_one({"_id": discord_id}) or {}
        eco_user = client["Economy"]["Users"].find_one({"_id": int(discord_id)}) or {}
        coins = eco_user.get("coins", 0)
        streak = eco_user.get("streak", 0)
        mention_count = 0
        mention_col = client["Mentions"]["Amount"]
        mention_doc = mention_col.find_one({"id": int(discord_id)})
        friend_doc = client["Website"]["FriendRequests"].find_one({"_id": discord_id}) or {}
        friend_count = len(friend_doc.get("friends", []))
        if mention_doc:
            mention_count = mention_doc.get("Mentions", 0)

    user_roles = user.get("roles", [])
    staff_badges = [STAFF_ROLES[int(rid)] for rid in user_roles if int(rid) in STAFF_ROLES]

    level = xp = message_count = 0
    boost_time_left = None
    rank = "?"
    progress_percent = 0
    current_xp = required_xp = 0
    current_xp_formatted = required_xp_formatted = "0"

    if level_doc:
        level = level_doc.get("level", 1)
        xp = level_doc.get("xp", 0)
        message_count = level_doc.get("message_count", 0)

        # XP Boost
        boost_until = level_doc.get("xp_boost_until")
        if boost_until:
            now = datetime.now(timezone.utc)
            if boost_until:
                if not isinstance(boost_until, datetime):
                    boost_until = boost_until.to_datetime()
                if boost_until.tzinfo is None:
                    boost_until = boost_until.replace(tzinfo=timezone.utc)

                if boost_until > now:
                    boost_time_left = str(boost_until - now).split(".")[0]

        # XP Progress Calculation
        def calc_required_xp(lvl):
            return 100 * (lvl ** 2) + 100 * lvl + 100

        prev_xp = calc_required_xp(level - 1) if level > 1 else 0
        next_xp = calc_required_xp(level)
        current_xp = xp - prev_xp
        required_xp = next_xp - prev_xp
        progress_percent = int((current_xp / required_xp) * 100)

        current_xp_formatted = f"{current_xp:,}"
        required_xp_formatted = f"{required_xp:,}"

        # Rank
        rank = next((i + 1 for i, u in enumerate(all_users) if u["_id"] == discord_id), "?")
    achievements = calculate_achievements(
        xp=xp,
        message_count=message_count,
        coins=coins,
        streak=streak,
        auctions_won=user.get("auctions_won", 0),
        top_bidder_count=user.get("top_bidder_count", 0),
        mentions=mention_count
    )


    return render_template(
        "profile.html",
        username=session.get("username"),
        display_name=session.get("display_name"),
        discord_id=discord_id,
        avatar_hash=session.get("avatar_hash"),
        roles=sorted_roles,
        highest_role=highest_role,
        level=level,
        xp=xp,
        message_count=message_count,
        boost_time_left=boost_time_left,
        progress_percent=progress_percent,
        current_xp_formatted=current_xp_formatted,
        required_xp_formatted=required_xp_formatted,
        rank=rank,
        mention_count=mention_count,
        is_owner=True, 
        user=user,
        staff_badges=staff_badges,
        streak=streak,
        coins=coins,
        achievements=achievements,
        friend_count=friend_count
    )

@app.route("/test-flash")
def test_flash():
    flash("✅ This is a test message!", "success")
    print("Flashed:", get_flashed_messages(with_categories=True))
    return redirect(url_for("profile"))


@csrf.exempt
@app.route("/toggle-privacy", methods=["POST"])
def toggle_privacy():
    if "discord_id" not in session:
        flash("Session expired. Please log in again.", "error")
        return redirect(url_for("login"))

    discord_id = session["discord_id"]
    users_collection = MongoClient(os.getenv("MONGO_URI"))["Website"]["users"]
    user = users_collection.find_one({"_id": discord_id})

    if user:
        new_value = not user.get("public_profile", True)
        users_collection.update_one(
            {"_id": discord_id},
            {"$set": {"public_profile": new_value}}
        )
        flash("✅ Profile visibility updated.", "success")

    return redirect(url_for("profile"))



@app.route("/leaderboard")
def leaderboard():
    page = int(request.args.get("page", 1))
    limit = 15
    skip = (page - 1) * limit
    lb_type = request.args.get("type", "level")

    with MongoClient(os.getenv("MONGO_URI")) as client:
        username_col = client["Website"]["usernames"]
        username_col2 = client["Website"]["users"]
        viewer_id = session.get("discord_id")
        viewer_profile = username_col2.find_one({"_id": str(viewer_id)}) if viewer_id else None

        is_staff = False
        if viewer_profile:
            user_roles = viewer_profile.get("roles", [])
            is_staff = any((role) in STAFF_ROLE_IDS for role in user_roles)

        level_col = client["hayday"]["level"]

        sort_field = {
            "level": "xp",
            "messages": "message_count",
            "streak": "streak",
            "mentions": "mention_count"
        }.get(lb_type, "xp")

        if lb_type == "streak":
            col = client["Economy"]["Users"]
            total_users = col.count_documents({"streak": {"$gt": 0}})
            users = list(col.find().sort("streak", -1).skip(skip).limit(limit))
            user_ids = [str(u["_id"]) for u in users]

        elif lb_type == "mentions":
            col = client["Mentions"]["Amount"]
            total_users = col.count_documents({"Mentions": {"$gt": 0}})
            users = list(col.find().sort("Mentions", -1).skip(skip).limit(limit))
            user_ids = [str(u["id"]) for u in users]

        elif lb_type == "hosted":
            col = client["Giveaway"]["current_giveaways"]
            total_users = len(list(col.aggregate([
                {"$match": {"host_id": {"$exists": True}}},
                {"$group": {"_id": "$host_id"}}
            ])))
            users = list(col.aggregate([
                {"$match": {"host_id": {"$exists": True}}},
                {"$group": {"_id": {"$toString": "$host_id"}, "hosted_count": {"$sum": 1}}},
                {"$sort": {"hosted_count": -1}},
                {"$skip": skip},
                {"$limit": limit}
            ]))
            user_ids = [u["_id"] for u in users]

        elif lb_type == "wins":
            col = client["Giveaway"]["current_giveaways"]
            total_users = len(list(col.aggregate([
                {"$match": {"winners": {"$exists": True}}},
                {"$unwind": "$winners"},
                {"$group": {"_id": "$winners"}}
            ])))
            users = list(col.aggregate([
                {"$match": {"winners": {"$exists": True}}},
                {"$unwind": "$winners"},
                {"$group": {"_id": "$winners", "won_count": {"$sum": 1}}},
                {"$sort": {"won_count": -1}},
                {"$skip": skip},
                {"$limit": limit}
            ]))
            user_ids = [u["_id"] for u in users]

        elif lb_type == "trivia":
            col = client["Economy"]["Users"]
            raw = list(col.find({"trivia_total": {"$gte": 5}}))
            total_users = len(raw)
            sorted_users = sorted(raw, key=lambda u: u.get("trivia_correct", 0) / max(u.get("trivia_total", 1), 1), reverse=True)
            users = sorted_users[skip:skip + limit]
            user_ids = [str(u["_id"]) for u in users]

        elif lb_type == "verifications":
            col = client["Verify"]["TopUsers"]
            all_staff = list(col.find({}))
            total_users = len(all_staff)

            # Sort and slice
            sorted_staff = sorted(all_staff, key=lambda u: u.get("Number of Verifications", 0), reverse=True)
            users = sorted_staff[skip:skip + limit]

            # 🔧 Make sure all user IDs are strings
            for user in users:
                user["_id"] = str(user["id"])

            user_ids = [user["_id"] for user in users]


        else:  # default = level or messages
            total_users = level_col.count_documents({})
            users = list(level_col.find().sort(sort_field, -1).skip(skip).limit(limit))
            user_ids = [u["_id"] for u in users]

        profiles = list(username_col.find({"_id": {"$in": user_ids}}))
        profile_map = {p["_id"]: p for p in profiles}

        for i, user in enumerate(users):
            uid = str(user["id"]) if lb_type == "mentions" else str(user["_id"])
            user["rank"] = skip + i + 1
            user["xp_formatted"] = f"{user.get('xp', 0):,}"
            user["level"] = user.get("level", 1)
            user["message_count"] = user.get("message_count", 0)
            user["mention_count"] = user.get("Mentions", 0)
            user["streak"] = user.get("streak", 0)

            profile = profile_map.get(uid)
            user["display_name"] = profile.get("display_name") or profile.get("username", "Unknown") if profile else f"<@{uid}>"
            user["avatar_url"] = profile.get("avatar") if profile else "https://cdn.discordapp.com/embed/avatars/0.png"
            user["is_boosting"] = profile.get("boosting", False) if profile else False
            user["hosted_count"] = user.get("hosted_count", 0)
            user["won_count"] = user.get("won_count", 0)
            user["trivia_correct"] = user.get("trivia_correct", 0)
            user["trivia_total"] = user.get("trivia_total", 0)

            if user["trivia_total"] > 0:
                user["trivia_percent"] = round((user["trivia_correct"] / user["trivia_total"]) * 100, 1)
            else:
                user["trivia_percent"] = 0.0
            user["verifications"] = user.get("Number of Verifications", 0)

    total_pages = (total_users + limit - 1) // limit
    if lb_type == "verifications":
        if not viewer_profile:
            return redirect("/leaderboard?type=level")

        user_roles = viewer_profile.get("roles", [])
        if not any(role in STAFF_ROLE_IDS for role in user_roles):
            return redirect("/leaderboard?type=level")



    return render_template("leaderboard.html", users=users, page=page, total_pages=total_pages, type=lb_type, viewer_id=viewer_id, is_staff=is_staff)




@app.route("/callback")
def callback():
    try:
        code = request.args.get("code")
        if not code:
            return "❌ Missing code from Discord redirect", 400

        data = {
            "client_id": DISCORD_CLIENT_ID,
            "client_secret": DISCORD_CLIENT_SECRET,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": DISCORD_REDIRECT_URI,
        }
        headers = {"Content-Type": "application/x-www-form-urlencoded"}

        r = requests.post("https://discord.com/api/oauth2/token", data=data, headers=headers)
        r.raise_for_status()
        access_token = r.json()["access_token"]

        user = requests.get(
            "https://discord.com/api/users/@me",
            headers={"Authorization": f"Bearer {access_token}"}
        ).json()

        GUILD_ID = "959220051427340379"  # Replace with your actual server ID

        member_res = requests.get(
            f"https://discord.com/api/users/@me/guilds/{GUILD_ID}/member",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        guild_data = requests.get(
            f"https://discord.com/api/guilds/{GUILD_ID}",
            headers={"Authorization": f"Bot {BOT_TOKEN}"}
        ).json()
        session.permanent = True
        session["guild_name"] = guild_data.get("name", "HayDay 🍀")
        if member_res.status_code == 200:
            member_data = member_res.json()
            session["display_name"] = member_data.get("nick") or user["username"]
            session["roles"] = member_data.get("roles", [])
        else:
            session["display_name"] = user["username"]
            session["roles"] = []

        session["discord_id"] = user["id"]
        session["username"] = user["username"] + "#" + user["discriminator"]
        session["avatar_hash"] = user["avatar"]
        with MongoClient(os.getenv("MONGO_URI")) as client:
            users_collection = client["Website"]["users"]

            users_collection.update_one(
                {"_id": user["id"]},
                {"$set": {
                    "username": user["username"] + "#" + user["discriminator"],
                    "display_name": member_data.get("nick") or user["username"],
                    "avatar_hash": user["avatar"],
                    "hay_day_id": None,  # Will be filled after linking
                    "linked_at": datetime.utcnow(),
                    "public_profile": True
                }},
                upsert=True
            )
            staff_collection = client["Website"]["Staff"]
            staff_doc = staff_collection.find_one({"_id": user["id"]})
            if staff_doc:
                session["staff_role"] = staff_doc.get("role", None)  # Use .get safely
            else:
                session["staff_role"] = None


        next_page = session.pop("next_page", url_for("profile"))
        print("User object:", user)  # <- add this too

        return redirect(next_page)
    except Exception as e:
        traceback.print_exc()
        return f"<h1>❌ Error:</h1><pre>{e}</pre>", 500

@app.route("/admin/purchases/export")
def export_purchases_csv():
    if not is_staff():
        return "Unauthorized", 403

    start = request.args.get("start")
    end = request.args.get("end")
    query = request.args.get("q", "").strip().lower()

    filter_ = {}
    if start or end:
        date_filter = {}
        if start:
            date_filter["$gte"] = datetime.fromisoformat(start)
        if end:
            date_filter["$lte"] = datetime.fromisoformat(end)
        filter_["timestamp"] = date_filter

    if query:
        filter_["$or"] = [
            {"item": {"$regex": query, "$options": "i"}},
            {"name": {"$regex": query, "$options": "i"}},
            {"user_id": {"$regex": query}}
        ]

    with MongoClient(os.getenv("MONGO_URI")) as client:
        purchases = list(
            client["Economy"]["Purchases"]
            .find(filter_)
            .sort("timestamp", -1)
        )

        user_ids = list({str(p["user_id"]) for p in purchases})
        users = client["Website"]["users"].find({"_id": {"$in": user_ids}})
        user_map = {u["_id"]: u for u in users}

    # Prepare CSV in memory
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["User ID", "Display Name", "Item", "Key", "Price", "Timestamp"])

    for p in purchases:
        uid = str(p["user_id"])
        user = user_map.get(uid)
        display_name = user.get("display_name") or user.get("username") if user else uid

        writer.writerow([
            uid,
            display_name,
            p.get("name", ""),
            p.get("item", ""),
            p.get("price", ""),
            p.get("timestamp").strftime("%Y-%m-%d %H:%M")
        ])

    output.seek(0)
    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=purchases.csv"}
    )

@app.route("/admin/users")
def admin_users():
    if not is_staff():
        return "Unauthorized", 403

    page = int(request.args.get("page", 1))
    query = request.args.get("q", "").strip().lower()
    per_page = 15
    search_filter = {}

    if query:
        search_filter["$or"] = [
            {"username": {"$regex": query, "$options": "i"}},
            {"_id": {"$regex": query}}
        ]

    with MongoClient(os.getenv("MONGO_URI")) as client:
        users_collection = client["Website"]["users"]

        total = users_collection.count_documents(search_filter)
        users = list(
            users_collection.find(search_filter)
            .sort("username", 1)
            .skip((page - 1) * per_page)
            .limit(per_page)
        )

    return render_template(
        "admin_users.html",
        users=users,
        query=query,
        page=page,
        total_pages=(total + per_page - 1) // per_page
    )

@csrf.exempt
@app.route("/admin/update-bio", methods=["POST"])
@csrf.exempt
def update_user_bio():
    if not is_staff():
        return "Unauthorized", 403

    user_id = request.form.get("user_id")
    is_clear = request.form.get("clear") == "1"
    new_bio = request.form.get("bio", "").strip()

    with MongoClient(os.getenv("MONGO_URI")) as client:
        users = client["Website"]["users"]
        if is_clear:
            users.update_one({"_id": user_id}, {"$unset": {"bio": ""}})
        elif new_bio:
            users.update_one({"_id": user_id}, {"$set": {"bio": new_bio}})

    return redirect(url_for("moderate_bios"))




@app.route("/admin/bios", methods=["GET", "POST"])
def moderate_bios():
    if not is_staff():
        return "Unauthorized", 403

    query = request.args.get("q", "").strip().lower()
    page = int(request.args.get("page", 1))
    per_page = 12
    filter_ = {"bio": {"$exists": True, "$ne": ""}}

    if query:
        filter_["$or"] = [
            {"username": {"$regex": query, "$options": "i"}},
            {"_id": {"$regex": query}}
        ]

    with MongoClient(os.getenv("MONGO_URI")) as client:
        users_col = client["Website"]["users"]
        total = users_col.count_documents(filter_)
        users = list(
            users_col.find(filter_)
            .sort("username", 1)
            .skip((page - 1) * per_page)
            .limit(per_page)
        )

    return render_template(
        "admin_bios.html",
        users=users,
        query=query,
        page=page,
        total_pages=(total + per_page - 1) // per_page
    )

@app.route("/directory")
def public_directory():
    query = request.args.get("q", "").lower()
    page = int(request.args.get("page", 1))
    page_size = 12

    users_collection = MongoClient(os.getenv("MONGO_URI"))["Website"]["users"]

    query_filter = {"public_profile": True}
    if query:
        query_filter["$or"] = [
            {"username": {"$regex": query, "$options": "i"}},
            {"hay_day_id": {"$regex": query, "$options": "i"}},
        ]

    total = users_collection.count_documents(query_filter)
    users = (
        users_collection.find(query_filter)
        .skip((page - 1) * page_size)
        .limit(page_size)
    )

    return render_template("directory.html",
                           users=list(users),
                           page=page,
                           total_pages=(total // page_size) + 1,
                           query=query)


@app.route("/profile-directory")
def profile_directory():
    search = request.args.get("search", "").strip()
    page = int(request.args.get("page", 1))
    per_page = 12

    users_collection = MongoClient(os.getenv("MONGO_URI"))["Website"]["users"]

    query = {}
    if search:
        query["$or"] = [
            {"username": {"$regex": search, "$options": "i"}},
            {"display_name": {"$regex": search, "$options": "i"}}
        ]

    total = users_collection.count_documents(query)
    raw_users = list(
        users_collection.find(query)
        .sort("display_name", 1)
        .skip((page - 1) * per_page)
        .limit(per_page)
    )

    users = []
    for user in raw_users:
        roles = user.get("roles", [])
        staff_badges = []
        for rid in roles:
            try:
                rid_int = int(rid)
                if rid_int in STAFF_ROLES:
                    staff_badges.append(STAFF_ROLES[rid_int])
            except ValueError:
                continue
        user["staff_badges"] = staff_badges

        users.append(user)



    total_pages = (total + per_page - 1) // per_page

    return render_template(
        "profile_directory.html",
        users=users,
        search=search,
        page=page,
        total_pages=total_pages
    )



@app.route("/profile/<discord_id>")
def public_profile(discord_id):
    # Defaults
    level = xp = message_count = boost_time_left = None
    progress_percent = current_xp_formatted = required_xp_formatted = rank = None

    viewer_id = session.get("discord_id")
    is_owner = viewer_id == discord_id

    with MongoClient(os.getenv("MONGO_URI")) as client:
        users_collection = client["Website"]["users"]
        user = users_collection.find_one({"_id": discord_id})

        if not user or not user.get("public_profile", False):
            return "🚫 This profile is private or does not exist.", 404

        user_roles = user.get("roles", [])
        staff_badges = [STAFF_ROLES[int(rid)] for rid in user_roles if int(rid) in STAFF_ROLES]

        eco_user = client["Economy"]["Users"].find_one({"_id": int(discord_id)}) or {}
        coins = eco_user.get("coins", 0)
        streak = eco_user.get("streak", 0)

        level_col = client["hayday"]["level"]
        level_doc = level_col.find_one({"_id": discord_id})

        mention_col = client["Mentions"]["Amount"]
        mention_doc = mention_col.find_one({"id": int(discord_id)})
        mention_count = mention_doc.get("Mentions", 0) if mention_doc else 0

        if level_doc:
            level = level_doc.get("level", 1)
            xp = level_doc.get("xp", 0)
            message_count = level_doc.get("message_count", 0)

            def calc_required_xp(lvl):
                return 100 * (lvl ** 2) + 100 * lvl + 100

            prev_xp = calc_required_xp(level - 1) if level > 1 else 0
            next_xp = calc_required_xp(level)
            current_xp = xp - prev_xp
            required_xp = next_xp - prev_xp
            progress_percent = int((current_xp / required_xp) * 100)

            current_xp_formatted = f"{current_xp:,}"
            required_xp_formatted = f"{required_xp:,}"

            all_users = list(level_col.find().sort("xp", -1))
            rank = next((i + 1 for i, u in enumerate(all_users) if u["_id"] == discord_id), "?")

    return render_template("profile.html",
        discord_id=user["_id"],
        display_name=user.get("display_name", "Unknown"),
        avatar_hash=user.get("avatar_hash", ""),
        user=user,
        staff_badges=staff_badges,
        level=level,
        xp=xp,
        message_count=message_count,
        mention_count=mention_count,
        boost_time_left=boost_time_left,
        progress_percent=progress_percent,
        current_xp_formatted=current_xp_formatted,
        required_xp_formatted=required_xp_formatted,
        rank=rank,
        roles=[],
        highest_role=None,
        coins=coins,
        streak=streak,
        is_owner=is_owner
    )



@csrf.exempt
@app.route("/buy", methods=["POST"])
def buy_item():
    if "discord_id" not in session:
        flash("⚠️ You need to log in to make a purchase.", "error")
        return redirect(url_for("login"))

    item_id = request.form.get("item_id")
    if not item_id or item_id not in SHOP_ITEMS:
        flash("❌ Unknown item.", "error")
        return redirect(url_for("shop"))

    user_id = int(session["discord_id"])
    item = SHOP_ITEMS[item_id]
    price = item["price"]

    with MongoClient(os.getenv("MONGO_URI")) as client:
        eco_col = client["Economy"]["Users"]
        web_col = client["Website"]["users"]

        # Fetch user from Economy DB
        user = eco_col.find_one({"_id": user_id}) or {}
        coins = user.get("coins", 0)

        if coins < price:
            flash("❌ You don't have enough coins for that.", "error")
            return redirect(url_for("shop"))

        # Deduct coins from both databases
        eco_col.update_one({"_id": user_id}, {"$inc": {"coins": -price}})
        web_col.update_one({"_id": str(user_id)}, {"$inc": {"coins": -price}}, upsert=True)

        # Inventory logic (Discord bot will check this)
        if item_id in ["mute_other_20m", "ping_storm", "ghost_ping", "lore_post"]:
            eco_col.update_one({"_id": user_id}, {"$inc": {f"{item_id}_used": 1}}, upsert=True)
        elif item_id in ["trivia_hint", "double_daily", "boosted_trivia", "mute_immunity"]:
            eco_col.update_one({"_id": user_id}, {"$set": {item_id: True}}, upsert=True)

        # Purchase log (optional)
        client["Economy"]["Purchases"].insert_one({
            "user_id": user_id,
            "item": item_id,
            "name": item["name"],
            "price": price,
            "timestamp": datetime.utcnow()
        })

    flash(f"✅ You bought {item['name']} for {price:,} coins!", "success")
    return redirect(url_for("shop"))

@app.route("/admin/purchases")
def view_purchases():
    if not is_staff():
        return "Unauthorized", 403

    query = request.args.get("q", "").strip().lower()
    start = request.args.get("start")
    end = request.args.get("end")
    page = int(request.args.get("page", 1))
    per_page = 20
    filter_ = {}

    # Handle date range
    if start or end:
        date_filter = {}
        if start:
            date_filter["$gte"] = datetime.fromisoformat(start)
        if end:
            date_filter["$lte"] = datetime.fromisoformat(end)
        filter_["timestamp"] = date_filter

    if query:
        filter_["$or"] = [
            {"item": {"$regex": query, "$options": "i"}},
            {"name": {"$regex": query, "$options": "i"}},
            {"user_id": {"$regex": query}}
        ]

    with MongoClient(os.getenv("MONGO_URI")) as client:
        purchases_col = client["Economy"]["Purchases"]
        user_col = client["Website"]["users"]

        total = purchases_col.count_documents(filter_)
        purchases = list(
            purchases_col.find(filter_)
            .sort("timestamp", -1)
            .skip((page - 1) * per_page)
            .limit(per_page)
        )

        user_ids = list({str(p["user_id"]) for p in purchases})
        users = list(user_col.find({"_id": {"$in": user_ids}}))
        user_map = {u["_id"]: u for u in users}

        for p in purchases:
            uid = str(p["user_id"])
            user = user_map.get(uid)
            p["display_name"] = user.get("display_name") or user.get("username") if user else uid

    return render_template(
        "admin_purchases.html",
        purchases=purchases,
        query=query,
        start=start,
        end=end,
        page=page,
        total_pages=(total + per_page - 1) // per_page
    )

@csrf.exempt
@app.route("/api/starboard/threshold", methods=["GET"])
def get_star_threshold():
    if not is_admin():
        return jsonify({"error": "Unauthorized"}), 403

    with MongoClient(os.getenv("MONGO_URI")) as client:
        col = client["hayday"]["starboard"]
        settings = col.find_one({"config": "starboard_settings"}) or {}
        threshold = settings.get("star_threshold", 5)

    # Convert Decimal128 or other Mongo types if necessary
    if isinstance(threshold, dict) and "$numberInt" in threshold:
        threshold = int(threshold["$numberInt"])

    return jsonify({"threshold": threshold})


@csrf.exempt
@app.route("/api/starboard/data")
def starboard_data():
    if not is_admin():
        return jsonify({"error": "Unauthorized"}), 403

    with MongoClient(os.getenv("MONGO_URI")) as client:
        col = client["hayday"]["starboard"]

        settings = col.find_one({"config": "starboard_settings"}) or {}
        starboard_entries = list(
            col.find({"starboard_message_id": {"$exists": True}})
            .sort("star_count", -1)
        )

        for entry in starboard_entries:
            entry["_id"] = str(entry["_id"])
            entry["star_count"] = int(entry.get("star_count", 0))
            entry["original_message_id"] = str(entry.get("original_message_id", ""))
            entry["starboard_message_id"] = str(entry.get("starboard_message_id", ""))

            # ✅ Add these two lines:
            entry["guild_id"] = str(entry.get("guild_id", ""))
            entry["channel_id"] = str(entry.get("channel_id", ""))


    return jsonify({
        "settings": {
            "star_threshold": int(settings.get("star_threshold", 5))
        },
        "entries": starboard_entries
    })



@csrf.exempt
@app.route("/api/starboard/delete", methods=["POST"])
def delete_starboard_message():
    if not is_admin():
        return jsonify({"error": "Unauthorized"}), 403

    data = request.get_json()
    message_id = str(data.get("message_id"))

    with MongoClient(os.getenv("MONGO_URI")) as client:
        col = client["hayday"]["starboard"]
        result = col.delete_one({"starboard_message_id": message_id})

    if result.deleted_count > 0:
        return jsonify({"message": "✅ Starboard message deleted."})
    else:
        return jsonify({"message": "❌ Message not found."})
    
@csrf.exempt
@app.route("/starboard-dashboard")
def starboard_dashboard():
    if not is_admin():  # optionally require stricter access than is_staff()
        return "Unauthorized", 403

    return render_template("starboard_dashboard.html", year=datetime.now().year)


@app.route("/auction-dashboard")
def auction_dashboard():
    if "discord_id" not in session:
        return redirect("/login-page")
    if not is_staff():
        return "Unauthorized", 403

    def fix_ids(doc):
        if isinstance(doc, list):
            return [fix_ids(x) for x in doc]
        if isinstance(doc, dict):
            new_doc = {}
            for k, v in doc.items():
                if isinstance(v, (ObjectId, int)) and k in {"_id", "message_id", "channel_id", "owner_id", "highest_bidder"}:
                    new_doc[k] = str(v)
                else:
                    new_doc[k] = fix_ids(v)
            return new_doc
        return doc

    active_page = int(request.args.get("active_page", 1))
    ended_page = int(request.args.get("ended_page", 1))
    log_page = int(request.args.get("log_page", 1))
    ban_page = int(request.args.get("ban_page", 1))
    limit = 12

    skip_active = (active_page - 1) * limit
    skip_ended = (ended_page - 1) * limit
    skip_logs = (log_page - 1) * limit
    skip_bans = (ban_page - 1) * limit

    with MongoClient(os.getenv("MONGO_URI")) as client:
        db = client["hayday"]
        user_col = client["Website"]["usernames"]
        log_col = client["Website"]["Logs"]

        active_auctions_all = list(db["auctions"].find({"status": "active"}))
        active_auctions_json = fix_ids(active_auctions_all)
        active_auctions = active_auctions_all[skip_active : skip_active + limit]

        ended_auctions = list(
            db["auctions"].find({"status": {"$in": ["ended", "no_bids"]}})
            .sort("end_time", -1)
            .skip(skip_ended).limit(limit)
        )
        logs = list(
            log_col.find({"type": {"$regex": "^auction_"}})
            .sort("timestamp", -1)
            .skip(skip_logs).limit(limit)
        )
        AUCTION_BANNED_ROLE_ID = 1379087489779630121
        banned_users = list(
            user_col.find({"roles": AUCTION_BANNED_ROLE_ID})
            .skip(skip_bans).limit(limit)
        )

        # Count total documents
        active_total = db["auctions"].count_documents({"status": "active"})
        ended_total = db["auctions"].count_documents({"status": {"$in": ["ended", "no_bids"]}})
        log_total = log_col.count_documents({"type": {"$regex": "^auction_"}})
        ban_total = user_col.count_documents({"roles": AUCTION_BANNED_ROLE_ID})

        active_total_pages = max((active_total + limit - 1) // limit, 1)
        ended_total_pages = max((ended_total + limit - 1) // limit, 1)
        log_total_pages = max((log_total + limit - 1) // limit, 1)
        ban_total_pages = max((ban_total + limit - 1) // limit, 1)

        # 🧠 Collect all user IDs
        user_ids = set()
        for auc in active_auctions + ended_auctions:
            user_ids.add(str(auc.get("owner_id")))
            user_ids.add(str(auc.get("highest_bidder")))
        for log in logs:
            if "author" in log and "id" in log["author"]:
                user_ids.add(str(log["author"]["id"]))
        for user in banned_users:
            user_ids.add(user["_id"])

        profiles = list(user_col.find({"_id": {"$in": list(user_ids)}}))
        user_map = {u["_id"]: u for u in profiles}

        for auc in active_auctions + ended_auctions:
            auc["owner_info"] = user_map.get(str(auc.get("owner_id")), {})
            auc["bidder_info"] = user_map.get(str(auc.get("highest_bidder")), {})
        for log in logs:
            author_id = str(log.get("author", {}).get("id"))
            log["author_info"] = user_map.get(author_id, {})
        for user in banned_users:
            user["display_name"] = user.get("display_name", user.get("username", "Unknown"))

    return render_template(
        "auction_dashboard.html",
        active_auctions=active_auctions,
        active_auctions_json=active_auctions_json,
        ended_auctions=ended_auctions,
        logs=logs,
        banned_users=banned_users,
        active_page=active_page,
        ended_page=ended_page,
        log_page=log_page,
        ban_page=ban_page,
        active_total_pages=active_total_pages,
        ended_total_pages=ended_total_pages,
        log_total_pages=log_total_pages,
        ban_total_pages=ban_total_pages,
        year=datetime.now().year
    )

@csrf.exempt
@app.route("/api/auction/cancel", methods=["POST"])
def cancel_auction():
    if "discord_id" not in session or not is_staff():
        return "Unauthorized", 403

    message_id = request.form.get("message_id")
    reason = request.form.get("reason") or "No reason provided."

    if not message_id:
        return "Missing message_id", 400

    # Update auction status to 'cancelled'
    with MongoClient(os.getenv("MONGO_URI")) as client:
        col = client["hayday"]["auctions"]
        auction = col.find_one({"message_id": int(message_id)})
        if not auction:
            return "Auction not found", 404

        col.update_one({"_id": auction["_id"]}, {"$set": {"status": "cancelled"}})

    # Notify bot to delete the Discord message and log
    requests.post(
        os.getenv("BOT_WEBHOOK_URL") + "/webhook/cancel-auction",
        json={
            "message_id": message_id,
            "reason": reason,
        },
        headers={"Authorization": os.getenv("BOT_WEBHOOK_KEY")}
    )

    return redirect("/auction-dashboard")


@csrf.exempt
@app.route("/api/auction/<message_id>/bids")
def get_auction_bids(message_id):
    if not is_staff():
        return "Unauthorized", 403

    with MongoClient(os.getenv("MONGO_URI")) as client:
        auction = client["hayday"]["auctions"].find_one({"message_id": int(message_id)})
        if not auction or "bid_logs" not in auction:
            return jsonify([])

        user_col = client["Website"]["usernames"]

        output = []
        user_ids = [str(bid["user_id"]) for bid in auction["bid_logs"]]
        user_map = {
            u["_id"]: u for u in user_col.find({"_id": {"$in": user_ids}})
        }

        for bid in auction["bid_logs"]:
            output.append({
                "user_display": user_map.get(str(bid["user_id"]), {}).get("display_name", str(bid["user_id"])),
                "user_id": str(bid["user_id"]),  # ← change from int() to str()
                "amount": bid["amount"],
                "timestamp": bid["timestamp"],
            })


        print("FINAL BIDS RETURNED:", output)

        return jsonify(output)

    
@csrf.exempt
@app.route("/api/auction/edit", methods=["POST"])
def edit_auction():
    if "discord_id" not in session or not is_staff():
        return "Unauthorized", 403

    def safe_int(val):
        try:
            return int(val)
        except (ValueError, TypeError):
            return None

    try:
        data = request.form.to_dict()
        message_id = int(data.get("message_id"))

        with MongoClient(os.getenv("MONGO_URI")) as client:
            col = client["hayday"]["auctions"]
            existing = col.find_one({"message_id": message_id})
            if not existing:
                return "Auction not found", 404

            update_fields = {}
            for k, v in data.items():
                if k == "message_id":
                    continue
                if k in ("quantity", "current_bid", "min_increment"):
                    parsed = safe_int(v)
                    if parsed is not None:
                        update_fields[k] = parsed
                else:
                    update_fields[k] = v

            image_url = data.get("image_url", "").strip()
            if not image_url and "image_url" in existing:
                image_url = existing["image_url"]
            update_fields["image_url"] = image_url

            col.update_one({"message_id": message_id}, {"$set": update_fields})

        # Notify bot
        requests.post(
            os.getenv("BOT_WEBHOOK_URL") + "/webhook/refresh-auction",
            json={"message_id": message_id},
            headers={"Authorization": os.getenv("BOT_WEBHOOK_KEY")}
        )
        print("[EDIT] Sent webhook for:", message_id)
        return redirect("/auction-dashboard")

    except Exception as e:
        return f"Error: {e}", 500
    
@csrf.exempt   
@app.route("/api/auction/remove-buyout", methods=["POST"])
def remove_buyout():
    if "discord_id" not in session or not is_staff():
        return "Unauthorized", 403
        
    message_id = request.form.get("message_id")

    if not message_id:
        return "Missing message_id", 400

    with MongoClient("MONGO_URI") as client:
        col = client["Auction"]["auctions"]
        result = col.update_one(
            {"message_id": int(message_id)},
            {"$unset": {"buyout_offer": ""}}
        )
        print(f"[BUYOUT REMOVE] message_id={message_id} matched={result.matched_count} modified={result.modified_count}")

    # Optionally trigger embed update via webhook
    try:
        requests.post(
            f"{os.getenv('WEBHOOK_BASE_URL')}/webhook/refresh-auction",
            headers={"Authorization": os.getenv("BOT_WEBHOOK_KEY")},
            json={"message_id": message_id}
        )
    except Exception as e:
        print(f"[WARN] Failed to refresh embed: {e}")

    return redirect("/auction-dashboard")

@csrf.exempt
@app.route("/api/auction/remove-image", methods=["POST"])
def remove_auction_image():
    if "discord_id" not in session or not is_staff():
        return "Unauthorized", 403
        
    message_id = request.form.get("message_id")

    with MongoClient(os.getenv("MONGO_URI")) as client:
        db = client["hayday"]["auctions"]
        result = db.update_one(
            {"message_id": int(message_id)},
            {"$unset": {"image_url": ""}}
        )
        print(f"[REMOVE-IMAGE] Result: matched={result.matched_count} modified={result.modified_count}")

    # Optional: refresh bot embed
    try:
        requests.post(
            f"{os.getenv('BOT_WEBHOOK_URL')}/webhook/refresh-auction",
            headers={"Authorization": os.getenv("BOT_WEBHOOK_KEY")},
            json={"message_id": message_id}
        )
    except Exception as e:
        print("Failed to refresh embed:", e)

    return redirect("/auction-dashboard")


@csrf.exempt
@app.route("/api/auction/end", methods=["POST"])
def end_auction_now():
    if "discord_id" not in session or not is_staff():
        return "Unauthorized", 403

    message_id = request.form.get("message_id")
    if not message_id:
        return "Missing message_id", 400

    with MongoClient(os.getenv("MONGO_URI")) as client:
        col = client["hayday"]["auctions"]
        auction = col.find_one({"message_id": int(message_id)})
        if not auction:
            return "Auction not found", 404

        # Force end by making it expired
        col.update_one({"_id": auction["_id"]}, {
            "$set": {"end_time": datetime.utcnow() - timedelta(seconds=1)}
        })

    # Trigger full auction end logic via bot webhook
    requests.post(
        os.getenv("BOT_WEBHOOK_URL") + "/webhook/end-auction",
        json={"message_id": message_id},
        headers={"Authorization": os.getenv("BOT_WEBHOOK_KEY")}
    )

    return redirect("/auction-dashboard")


@csrf.exempt
@app.route("/api/auction/<message_id>/remove-bid", methods=["POST"])
def remove_auction_bid(message_id):
    if "discord_id" not in session or not is_staff():
        return "Unauthorized", 403

    user_id = request.form.get("user_id")
    print("[REMOVE BID] Raw user_id from form:", user_id)

    if not user_id:
        return "Missing user_id", 400

    try:
        user_id_int = int(user_id)
    except ValueError:
        return "Invalid user_id format", 400

    print("[REMOVE BID] Target user_id to remove (int):", user_id_int)

    with MongoClient(os.getenv("MONGO_URI")) as client:
        auctions = client["hayday"]["auctions"]
        auction = auctions.find_one({"message_id": int(message_id)})

        if not auction:
            print("[REMOVE BID] ❌ Auction not found.")
            return "Auction not found", 404

        bid_logs = auction.get("bid_logs", [])
        print(f"[REMOVE BID] Found {len(bid_logs)} bids before removal")

        for bid in bid_logs:
            print(f"[COMPARE] bid.user_id={bid['user_id']} (type: {type(bid['user_id'])}) vs {user_id_int} (type: {type(user_id_int)})")

        updated_logs = [bid for bid in bid_logs if str(bid["user_id"]) != str(user_id_int)]
        for bid in bid_logs:
            print(f"[CHECK] str({bid['user_id']}) = {str(bid['user_id'])}, form = {str(user_id_int)}")


        print(f"[REMOVE BID] Bids after removal: {len(updated_logs)}")

        if len(updated_logs) == len(bid_logs):
            print("[REMOVE BID] ⚠ No bid found for this user_id — nothing removed")

        # Recalculate highest bid
        if updated_logs:
            updated_logs.sort(key=lambda x: x["timestamp"])
            last = updated_logs[-1]
            current_bid = last["amount"]
            highest_bidder = last["user_id"]
        else:
            current_bid = auction.get("starting_bid", 0)
            highest_bidder = None

        result = auctions.update_one(
            {"message_id": int(message_id)},
            {"$set": {
                "bid_logs": updated_logs,
                "current_bid": current_bid,
                "highest_bidder": highest_bidder
            }}
        )

        print(f"[REMOVE BID] Mongo matched: {result.matched_count}, modified: {result.modified_count}")
        print(f"[REMOVE BID] New highest_bidder: {highest_bidder}, current_bid: {current_bid}")

    # Trigger refresh
    refresh_resp = requests.post(
        os.getenv("BOT_WEBHOOK_URL") + "/webhook/refresh-auction",
        json={"message_id": message_id},
        headers={"Authorization": os.getenv("BOT_WEBHOOK_KEY")}
    )

    print(f"[REMOVE BID] Webhook refresh response: {refresh_resp.status_code}")
    return redirect("/auction-dashboard")



@app.route("/webhook/refresh-auction", methods=["POST"])
def refresh_auction_webhook():
    if request.headers.get("X-Webhook-Secret") != os.getenv("BOT_WEBHOOK_KEY"):
        return "Forbidden", 403

    data = request.get_json()
    message_id = data.get("message_id")

    # TODO: Optionally add logic to notify the bot or update cache, etc.
    print(f"[Webhook] Refresh auction triggered for message ID: {message_id}")

    return "OK", 200

@app.route("/admin/refund", methods=["POST"])
@csrf.exempt
def refund_purchase():
    if not is_admin():  # optionally require stricter access than is_staff()
        return "Unauthorized", 403

    purchase_id = request.form.get("purchase_id")
    if not purchase_id:
        return "Invalid request", 400

    with MongoClient(os.getenv("MONGO_URI")) as client:
        purchases_col = client["Economy"]["Purchases"]
        eco_col = client["Economy"]["Users"]

        purchase = purchases_col.find_one({"_id": ObjectId(purchase_id)})
        if not purchase or purchase.get("refunded"):
            return "Already refunded or not found", 400

        # Refund coins
        eco_col.update_one(
            {"_id": int(purchase["user_id"])},
            {"$inc": {"coins": purchase["price"]}}
        )

        # Revert item usage if tracked
        item_id = purchase["item"]
        if item_id in ["mute_other_20m", "ping_storm", "ghost_ping", "lore_post"]:
            eco_col.update_one(
                {"_id": int(purchase["user_id"])},
                {"$inc": {f"{item_id}_used": -1}}
            )
        elif item_id in ["trivia_hint", "double_daily", "boosted_trivia", "mute_immunity"]:
            eco_col.update_one(
                {"_id": int(purchase["user_id"])},
                {"$set": {item_id: False}}
            )

        purchases_col.update_one(
            {"_id": ObjectId(purchase_id)},
            {"$set": {"refunded": True, "refunded_at": datetime.utcnow()}}
        )

    flash("✅ Purchase refunded successfully.", "success")
    return redirect(url_for("view_purchases"))



@app.route("/logout")
def logout():
    next_page = request.args.get("next", "/")
    session.clear()
    return redirect(next_page)



class SubmitForm(FlaskForm):
    hay_day_id = StringField("Hay Day ID", validators=[DataRequired()])
    discord_id = StringField("Discord ID", validators=[DataRequired()])
    fingerprint = HiddenField("Fingerprint")
    # You can later add a `captcha_response = HiddenField()` here

@app.route("/terms")
def terms_page():
    year = datetime.now().year
    return render_template("terms.html", year=year)


@app.route("/privacy")
def privacy_page():
    year = datetime.now().year
    return render_template("privacy.html", year=year)



@app.route("/staff")
def staff_panel():
    with MongoClient(os.getenv("MONGO_URI")) as client:
        staff = list(client["Website"]["Staff"].find())
    year = datetime.now(timezone.utc).year
    return render_template("staff.html", staff=staff, year=year)

@app.route("/dashboard")
def dashboard():
    if "discord_id" not in session:
        return redirect("/login-page")

    with MongoClient(os.getenv("MONGO_URI")) as client:
        settings_col = client["Website"]["bot_settings"]
        settings = settings_col.find_one({"_id": "settings"}) or {}

    return render_template(
        "dashboard.html",
        year=datetime.now().year,
        username=session.get("username", "Unknown"),
        prefix=settings.get("prefix", "!")
    )

@csrf.exempt
@app.route("/api/update-setting", methods=["POST"])
def update_setting():
    if not is_staff():
        return "Unauthorized", 403    
    if "discord_id" not in session:
        return jsonify({"error": "Not logged in"}), 401

    data = request.get_json(force=True)
    key = data.get("key")
    value = data.get("value")

    if key != "prefix":
        return jsonify({"error": "Invalid setting"}), 400

    with MongoClient(os.getenv("MONGO_URI")) as client:
        settings_col = client["Website"]["bot_settings"]
        settings_col.update_one({"_id": "settings"}, {"$set": {key: value}}, upsert=True)

    return jsonify({"message": "Prefix updated successfully!"})

@app.route("/giveaway-dashboard")
def giveaway_dashboard():
    if not is_staff():
        return redirect("/")

    return render_template(
        "giveaway_dashboard.html",
        BOT_WEBHOOK_KEY=os.getenv("BOT_WEBHOOK_KEY"),
        username=session.get("username", "Unknown"),
        year=datetime.now().year
    )



@csrf.exempt
@app.route("/api/giveaways/edit/<message_id>", methods=["POST"])
def edit_giveaway(message_id):
    if not is_staff():
        return "Unauthorized", 403    
        
    if "discord_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    try:
        data = request.json if request.is_json else request.get_json()
        payload = {
            "message_id": message_id,
            "updates": data
        }

        webhook_url = os.getenv("BOT_WEBHOOK_URL") + "/webhook/edit-giveaway"
        headers = {"Authorization": os.getenv("BOT_WEBHOOK_KEY", "")}
        res = requests.post(webhook_url, json=payload, headers=headers)

        return jsonify(res.json()), res.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500




@csrf.exempt
@app.route("/api/giveaways", methods=["GET"])
def get_giveaways():
    if "discord_id" not in session:
        return jsonify([])
    guild_id = "959220051427340379"  # your server ID
    try:
        role_mapping = fetch_role_mapping(guild_id)
    except Exception as e:
        print(f"[API Giveaways] Failed to fetch role mapping: {e}")
        role_mapping = {}


    now_ts = time.time()

    with MongoClient(os.getenv("MONGO_URI")) as client:
        db = client["Giveaway"]
        giveaways = []

        for g in db["current_giveaways"].find({"ended": False}):
            end = g.get("end_time")
            if not end:
                continue
            if end.timestamp() < now_ts:
                continue

            delta = int(end.timestamp() - now_ts)
            minutes = (delta % 3600) // 60
            ends_in = f"{delta // 3600}h {minutes}m"

            giveaways.append({
                "prize": g.get("prize", "N/A"),
                "winners": g.get("winners_count", 1),
                "message_id": str(g.get("message_id")),
                "entry_count": sum(g.get("participants", {}).values()),
                "participant_count": len(g.get("participants", {})),
                "ends_in": ends_in,
                "host_id": g.get("host_id"),
                "required_role_id": g.get("required_role_id"),
                "required_role_name": role_mapping.get(str(g.get("required_role_id")), {}).get("name") if g.get("required_role_id") else None,
                "color": g.get("color")
            })

        # ✅ This part must be OUTSIDE the loop
        recently_ended = list(
            db["current_giveaways"]
            .find({"ended": True})
            .sort("end_time", -1)
            .limit(10)
        )

        ended_giveaways = []
        for g in recently_ended:
            ended_giveaways.append({
                "prize": g.get("prize", "N/A"),
                "winners": g.get("winners_count", 1),
                "message_id": str(g.get("message_id")),
                "ended_at": g.get("end_time").strftime("%Y-%m-%d %H:%M")
            })

    return jsonify({
        "active": giveaways,
        "ended": ended_giveaways
    })


@app.route("/api/giveaways/recent", methods=["GET"])
@csrf.exempt
def recent_giveaways():
    if "discord_id" not in session:
        return jsonify([])

    skip = int(request.args.get("skip", 0))
    limit = int(request.args.get("limit", 9))

    with MongoClient(os.getenv("MONGO_URI")) as client:
        db = client["Giveaway"]
        userdb = client["Website"]["usernames"]

        ended = list(db["current_giveaways"]
                     .find({"ended": True})
                     .sort("end_time", -1)
                     .skip(skip)
                     .limit(limit))

        # Collect host + winner IDs
        host_ids = [str(g.get("host_id")) for g in ended if g.get("host_id")]
        winner_ids = [str(uid) for g in ended for uid in g.get("winners", [])]

        # Fetch profiles in one batch
        user_profiles = userdb.find({"_id": {"$in": list(set(host_ids + winner_ids))}})
        user_map = {u["_id"]: u for u in user_profiles}

        results = []
        for g in ended:
            host_id = str(g.get("host_id"))
            host = user_map.get(host_id, {})
            
            winner_buttons = []
            for uid in g.get("winners", []):
                u = user_map.get(str(uid))
                winner_buttons.append({
                    "id": str(uid),
                    "name": u.get("display_name") or u.get("username") if u else f"User {uid}"
                })

            results.append({
                "prize": g.get("prize", "N/A"),
                "winners": g.get("winners_count", 1),
                "message_id": str(g.get("message_id")),
                "ended_at": g.get("end_time").strftime("%Y-%m-%d %H:%M"),
                "host_name": host.get("display_name", f"<@{host_id}>"),
                "host_avatar": host.get("avatar", "https://cdn.discordapp.com/embed/avatars/0.png"),
                "winner_buttons": winner_buttons,
            })

    return jsonify(results)



@csrf.exempt
@app.route("/api/giveaways/end/<message_id>", methods=["POST"])
def end_giveaway(message_id):
    if not is_staff():
        return "Unauthorized", 403    

    if "discord_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    try:
        webhook_url = os.getenv("BOT_WEBHOOK_URL") + "/webhook/end-giveaway"
        headers = {"Authorization": os.getenv("BOT_WEBHOOK_KEY", "")}
        payload = {
            "message_id": int(message_id),
            "action": "end"
        }

        res = requests.post(webhook_url, json=payload, headers=headers)
        return jsonify(res.json()), res.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@csrf.exempt
@app.route("/api/giveaways/winners/<message_id>")
def get_winners(message_id):
    try:
        with MongoClient(os.getenv("MONGO_URI")) as client:
            db = client["Giveaway"]
            g = db["current_giveaways"].find_one({"message_id": int(message_id)})
            if not g or "winners" not in g or not g["winners"]:
                return jsonify([])

            user_ids = g["winners"]

            # ✅ Use the usernames collection (not hayday.level)
            user_db = client["Website"]["usernames"]
            found_users = list(user_db.find({"_id": {"$in": [str(uid) for uid in user_ids]}}))
            user_map = {str(u["_id"]): u for u in found_users}

            # ✅ Build result with avatar + display name fallback
            result = []
            for uid in user_ids:
                user = user_map.get(str(uid))
                result.append({
                    "id": str(uid),
                    "username": user.get("display_name", f"<@{uid}>") if user else f"<@{uid}>",
                    "avatar": user.get("avatar") if user else None
                })

            return jsonify(result)

    except Exception as e:
        return jsonify({"error": str(e)}), 500

    

@app.route("/api/giveaways/delete", methods=["POST"])
@csrf.exempt
def delete_giveaway():
    if not is_staff():
        return "Unauthorized", 403

    data = request.get_json()
    message_id = int(data.get("message_id"))

    if not message_id:
        return jsonify({"error": "Missing message ID"}), 400

    try:
        with MongoClient(os.getenv("MONGO_URI")) as client:
            collection = client["Giveaway"]["current_giveaways"]
            giveaway = collection.find_one({"message_id": message_id})

            if not giveaway:
                return jsonify({"error": "Giveaway not found"}), 404

            # Delete from Discord
            bot_token = os.getenv("DISCORD_BOT_TOKEN")
            headers = {"Authorization": f"Bot {bot_token}"}
            channel_id = giveaway.get("channel_id")
            if channel_id:
                try:
                    requests.delete(
                        f"https://discord.com/api/v10/channels/{channel_id}/messages/{message_id}",
                        headers=headers
                    )
                except Exception as e:
                    print(f"[Force Delete] Discord message delete failed: {e}")

            # Delete from DB
            collection.delete_one({"message_id": message_id})
            return jsonify({"message": "Giveaway deleted successfully."})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

    
@csrf.exempt
@app.route("/api/giveaways/reroll-specific", methods=["POST"])
def reroll_specific():
    if not is_staff():
        return "Unauthorized", 403    
    token = request.headers.get("Authorization") or session.get("discord_id")
    if not token:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    message_id = int(data["message_id"])
    user_id = int(data["user_id"])

    try:
        reroll_url = os.getenv("BOT_REROLL_URL")
        r = requests.post(
            reroll_url,
            json={"message_id": message_id, "user_id": user_id},
            headers={"Authorization": os.getenv("BOT_WEBHOOK_KEY")}
        )
        return jsonify(r.json()), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500



@csrf.exempt
@app.route("/api/giveaways/reroll/<message_id>", methods=["POST"])
def reroll_giveaway(message_id):
    if not is_staff():
        return "Unauthorized", 403

    if "discord_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    try:
        webhook_url = os.getenv("BOT_WEBHOOK_URL") + "/webhook/reroll-giveaway"
        headers = {"Authorization": os.getenv("BOT_WEBHOOK_KEY", "")}
        payload = {"message_id": int(message_id)}

        res = requests.post(webhook_url, json=payload, headers=headers)
        return jsonify(res.json()), res.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@csrf.exempt
@app.route("/giveaway/join", methods=["POST"])
def join_giveaway_web():
    if "discord_id" not in session:
        return redirect("/login")

    message_id = request.form.get("message_id")
    discord_id = str(session["discord_id"])
    user_roles = session.get("roles", [])  # List of role IDs as strings
    booster_role_id = "975188431636418681"

    with MongoClient(os.getenv("MONGO_URI")) as client:
        col = client["Giveaway"]["current_giveaways"]
        giveaway = col.find_one({"message_id": int(message_id)})

        if not giveaway or giveaway.get("ended"):
            flash("❌ Giveaway not found or has ended.")
            return redirect("/giveaways")

        required_role_id = str(giveaway.get("required_role_id")) if giveaway.get("required_role_id") else None

        # ✅ Required role check (same logic as bot)
        if required_role_id and required_role_id not in user_roles and booster_role_id not in user_roles:
            flash(f"❌ You don’t have the required role to enter this giveaway.")
            return redirect("/giveaways")

        participants = giveaway.get("participants", {})
        if discord_id in participants:
            flash("❌ You are already entered in this giveaway.")
            return redirect("/giveaways")

        extra_entries = 2 if booster_role_id in user_roles else 1
        participants[discord_id] = extra_entries

        col.update_one({"message_id": int(message_id)}, {"$set": {"participants": participants}})

        # ✅ Trigger bot webhook to refresh Discord message
        try:
            requests.post(
                os.getenv("BOT_WEBHOOK_URL") + "/webhook/refresh-giveaway",
                json={"message_id": int(message_id)},
                headers={"Authorization": os.getenv("BOT_WEBHOOK_KEY")}
            )
        except Exception as e:
            print(f"⚠️ Failed to sync with bot: {e}")

        flash("✅ You have joined the giveaway.")
        return redirect("/giveaways")



@csrf.exempt
@app.route("/giveaway/leave", methods=["POST"])
def leave_giveaway_web():
    if "discord_id" not in session:
        return redirect("/login")

    message_id = request.form.get("message_id")
    discord_id = str(session["discord_id"])

    with MongoClient(os.getenv("MONGO_URI")) as client:
        col = client["Giveaway"]["current_giveaways"]
        giveaway = col.find_one({"message_id": int(message_id)})

        if not giveaway or giveaway.get("ended"):
            flash("❌ Giveaway not found or already ended.")
            return redirect("/giveaways")

        participants = giveaway.get("participants", {})
        if discord_id not in participants:
            flash("❌ You are not in this giveaway.")
            return redirect("/giveaways")

        del participants[discord_id]
        col.update_one({"message_id": int(message_id)}, {"$set": {"participants": participants}})

        # ✅ Sync with the bot to refresh the giveaway button
        try:
            requests.post(
                os.getenv("BOT_WEBHOOK_URL") + "/webhook/refresh-giveaway",
                json={"message_id": int(message_id)},
                headers={"Authorization": os.getenv("BOT_WEBHOOK_KEY")}
            )
        except Exception as e:
            print(f"⚠️ Failed to sync with bot after leave: {e}")

        flash("✅ You have left the giveaway.")
        return redirect("/giveaways")


@csrf.exempt
@app.route("/api/giveaways/reroll", methods=["POST"])
def reroll_giveaway_post():
    if not is_staff():
        return "Unauthorized", 403

    if "discord_id" not in session:
        return jsonify({"error": "Not logged in"}), 401

    try:
        data = request.get_json(force=True)
        message_id = int(data.get("message_id"))
        action = data.get("action", "reroll")
    except Exception as e:
        return jsonify({"error": f"Invalid input: {e}"}), 400

    bot_url = os.getenv("BOT_WEBHOOK_URL")
    auth_header = os.getenv("BOT_WEBHOOK_KEY")

    try:
        res = requests.post(
            bot_url,
            json={"message_id": message_id, "action": action},
            headers={"Authorization": auth_header}
        )
        print("✅ Forwarded reroll to bot:", res.status_code, res.text)
        return res.json(), res.status_code
    except Exception as e:
        print("❌ Failed to contact bot:", e)
        return jsonify({"error": f"Request failed: {e}"}), 500




if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    env = os.getenv("FLASK_ENV", "prod")

    if env == "dev":
        # Local dev with livereload

        logging.getLogger("livereload").setLevel(logging.WARNING)

        server = Server(app)
        server.watch('templates/')
        server.watch('static/')
        server.serve(host='127.0.0.1', port=port)
    else:
        # Production for Fly.io
        app.run(host="0.0.0.0", port=port)

