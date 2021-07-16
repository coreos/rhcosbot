#!/usr/bin/python3
#
# Apache 2.0 license

import argparse
import bugzilla
from dotted_dict import DottedDict
from functools import reduce, wraps
import os
import signal
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from slack_sdk.socket_mode import SocketModeClient
from slack_sdk.socket_mode.response import SocketModeResponse
import sqlite3
import time
import traceback
import yaml

ISSUE_LINK = 'https://github.com/bgilbert/rhcosbot/issues'
HELP = f'''
I understand these commands:
`ping` - check whether the bot is running properly
`help` - print this message
Report problems <{ISSUE_LINK}|here>.
'''

def escape(message):
    '''Escape a string for inclusion in a Slack message.'''
    # https://api.slack.com/reference/surfaces/formatting#escaping
    map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
    }
    return reduce(lambda s, p: s.replace(p[0], p[1]), map.items(), message)


class Database:
    def __init__(self, config):
        self._db = sqlite3.connect(config.database)
        with self:
            ver = self._db.execute('pragma user_version').fetchone()[0]
            if ver < 1:
                self._db.execute('create table events '
                        '(added integer not null, '
                        'channel text not null, '
                        'timestamp text not null)')
                self._db.execute('create unique index events_unique '
                        'on events (channel, timestamp)')
                self._db.execute('pragma user_version = 1')

    def __enter__(self):
        '''Start a database transaction.'''
        return self._db.__enter__()

    def __exit__(self, *args, **kwargs):
        '''Commit a database transaction.'''
        return self._db.__exit__(*args, **kwargs)

    def add_event(self, channel, ts):
        '''Return False if the event is already present.'''
        try:
            self._db.execute('insert into events (added, channel, timestamp) '
                    'values (?, ?, ?)', (int(time.time()), channel, ts))
            return True
        except sqlite3.IntegrityError:
            return False

    def prune_events(self, max_age=3600):
        self._db.execute('delete from events where added < ?',
                (int(time.time() - max_age),))


def report_errors(f):
    '''Decorator that sends exceptions to an administrator via Slack DM
    and then swallows them.  The first argument of the function must be
    the config.'''
    import json, requests, socket, urllib.error
    @wraps(f)
    def wrapper(config, *args, **kwargs):
        try:
            return f(config, *args, **kwargs)
        except (json.JSONDecodeError, requests.ConnectionError, requests.HTTPError, requests.ReadTimeout) as e:
            # Exception type leaked from the bugzilla API.  Assume transient
            # network problem; don't send message.
            print(e)
        except (socket.timeout, urllib.error.URLError) as e:
            # Exception type leaked from the slack_sdk API.  Assume transient
            # network problem; don't send message.
            print(e)
        except Exception as e:
            try:
                message = f'Caught exception:\n```\n{traceback.format_exc()}```'
                client = WebClient(token=config.slack_token)
                channel = client.conversations_open(users=[config.error_notification])['channel']['id']
                client.chat_postMessage(channel=channel, text=message)
            except Exception as e:
                traceback.print_exc()
    return wrapper


@report_errors
def process_event(config, socket_client, req):
    '''Handler for a Slack event.'''
    client = socket_client.web_client
    payload = DottedDict(req.payload)
    db = Database(config)
    bzapi = bugzilla.Bugzilla(config.bugzilla, api_key=config.bugzilla_key,
            force_rest=True)

    def ack_event():
        '''Acknowledge the event, as required by Slack.'''
        resp = SocketModeResponse(envelope_id=req.envelope_id)
        socket_client.send_socket_mode_response(resp)

    def complete_command():
        '''Add a success emoji to a command mention.'''
        client.reactions_add(channel=payload.event.channel,
                name='ballot_box_with_check', timestamp=payload.event.ts)

    def fail_command(message):
        '''Reply to a command mention with an error.'''
        client.chat_postMessage(channel=payload.event.channel,
                text=f"<@{payload.event.user}> {message}",
                # start a new thread or continue the existing one
                thread_ts=payload.event.get('thread_ts', payload.event.ts))

    with db:
        if req.type == 'events_api' and payload.event.type == 'app_mention':
            if payload.event.channel != config.channel:
                # Don't even acknowledge events outside our channel, to
                # avoid interfering with separate instances in other
                # channels.
                return
            ack_event()
            if not db.add_event(payload.event.channel, payload.event.event_ts):
                # When we ignore some events, Slack can send us duplicate
                # retries.  Detect and ignore those after acknowledging.
                return
            message = payload.event.text.replace(f'<@{config.bot_id}>', '').strip()
            if message == 'ping':
                # Check Bugzilla connectivity
                try:
                    if not bzapi.logged_in:
                        raise Exception('Not logged in.')
                except Exception:
                    # Swallow exception details and just report the failure
                    fail_command('Cannot contact Bugzilla.')
                    return
                complete_command()
            elif message == 'help':
                client.chat_postMessage(channel=payload.event.channel, text=HELP,
                        # start a new thread or continue the existing one
                        thread_ts=payload.event.get('thread_ts', payload.event.ts))
            elif message == 'throw':
                # undocumented
                complete_command()
                raise Exception(f'Throwing exception as requested by <@{payload.event.user}>')
            else:
                fail_command(f"I didn't understand that.  Try `<@{config.bot_id}> help`")


def main():
    parser = argparse.ArgumentParser(
            description='Bugzilla helper bot for Slack.')
    parser.add_argument('-c', '--config', metavar='FILE',
            default='~/.rhcosbot', help='config file')
    parser.add_argument('-d', '--database', metavar='FILE',
            default='~/.rhcosbot-db', help='database file')
    args = parser.parse_args()

    # Read config
    with open(os.path.expanduser(args.config)) as fh:
        config = DottedDict(yaml.safe_load(fh))
        config.database = os.path.expanduser(args.database)
    env_map = (
        ('RHCOSBOT_SLACK_APP_TOKEN', 'slack-app-token'),
        ('RHCOSBOT_SLACK_TOKEN', 'slack-token'),
        ('RHCOSBOT_BUGZILLA_KEY', 'bugzilla-key')
    )
    for env, config_key in env_map:
        v = os.environ.get(env)
        if v:
            setattr(config, config_key, v)

    # Connect to services
    client = WebClient(token=config.slack_token)
    # store our user ID
    config.bot_id = client.auth_test()['user_id']
    bzapi = bugzilla.Bugzilla(config.bugzilla, api_key=config.bugzilla_key,
            force_rest=True)
    if not bzapi.logged_in:
        raise Exception('Did not authenticate')
    db = Database(config)

    # Start socket-mode listener in the background
    socket_client = SocketModeClient(app_token=config.slack_app_token,
            web_client=WebClient(token=config.slack_token))
    socket_client.socket_mode_request_listeners.append(
            lambda socket_client, req: process_event(config, socket_client, req))
    socket_client.connect()

    while True:
        signal.pause()


if __name__ == '__main__':
    main()
