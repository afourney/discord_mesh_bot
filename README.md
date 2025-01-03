# discord\_mesh\_bot
Simple script for relaying meshtastic messages onto Discord.

To get going, you should create a `webhooks.bash` script that sets the appropriate environment variables for the webhooks:

```bash
# File: webhooks.bash
export DISCORD_WEBHOOK='https://discord.com/api/webhooks/...'
export TEST_WEBHOOK='https://discord.com/api/webhooks/...'
```

Then set up your python virtual environment
```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

The run the bot
```bash
bash mqtt.bash
```
