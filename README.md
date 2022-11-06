# RHCOS bot

This is a Slack bot to help with managing RHCOS backports and bootimage bumps.  It is stateless (except for some replay protection on Slack messages) and command-driven, pulling all of its data from Jira.

## Installing

A `setup.cfg` would be nice, but we don't have one right now.

```sh
cd ~
git clone https://github.com/coreos/rhcosbot
cd rhcosbot
virtualenv env
env/bin/pip install -r requirements.txt
env/bin/python rhcosbot.py
```

Alternatively, a [container image](https://quay.io/repository/coreos/rhcosbot) is available.

You'll also need to set up a Slack app in your workspace and get an API token for it, and to get a Jira API key.

## Slack scopes

- `app_mentions:read` - receive commands via mentions in channel
- `chat:write` - send threaded replies to channel
- `im:write` - send error reports to the bot administrator
- `reactions:write` - react to command messages to indicate status

## Config format

See [config.example](config.example).  Put this in `~/.rhcosbot` by default.
