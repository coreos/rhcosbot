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
import threading
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
        self._db.__enter__()
        return self

    def __exit__(self, exc_type, exc_value, tb):
        '''Commit a database transaction.'''
        if exc_type is HandledError:
            # propagate exception but commit anyway
            self._db.__exit__(None, None, None)
            return False
        return self._db.__exit__(exc_type, exc_value, tb)

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


class HandledError(Exception):
    '''An exception which should just be swallowed.'''
    pass


def report_errors(f):
    '''Decorator that sends exceptions to an administrator via Slack DM
    and then swallows them.  The first argument of the function must be
    the config.'''
    import json, requests, socket, urllib.error
    @wraps(f)
    def wrapper(config, *args, **kwargs):
        try:
            return f(config, *args, **kwargs)
        except HandledError:
            pass
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


class Registry(type):
    '''Metaclass that creates a dict of functions registered with the
    register decorator.'''

    def __new__(cls, name, bases, attrs):
        cls = super().__new__(cls, name, bases, attrs)
        registry = {}
        for f in attrs.values():
            command = getattr(f, '_command', None)
            if command is not None:
                registry[command] = f
        cls._registry = registry
        return cls


def register(*args):
    '''Decorator that registers the subcommand handled by a function.'''
    def decorator(f):
        f._command = tuple(args)
        return f
    return decorator


class CommandHandler(metaclass=Registry):
    '''Wrapper class to handle a single event in a thread.  Creates its own
    network clients for thread safety.'''

    def __init__(self, config, event):
        self._config = config
        self._event = event
        self._client = WebClient(token=config.slack_token)
        self._bzapi = bugzilla.Bugzilla(config.bugzilla,
                api_key=config.bugzilla_key, force_rest=True)
        self._called = False

    def __call__(self):
        assert not self._called
        self._called = True

        message = self._event.text.replace(f'<@{self._config.bot_id}>', '').strip()
        words = message.split()
        # Match the longest available subcommand
        for count in range(len(words), 0, -1):
            f = self._registry.get(tuple(words[:count]))
            if f is not None:
                # report_errors() requires the config to be the first argument
                threading.Thread(
                    target=report_errors(lambda _config, f, *args: f(*args)),
                    name=f.__name__,
                    args=(self._config, f, self, *words[count:])
                ).start()
                return

        # Tried all possible subcommand lengths, found nothing in registry
        self._reply(f"I didn't understand that.  Try `<@{self._config.bot_id}> help`")

    def _complete(self):
        '''Add a success emoji to a command mention.'''
        self._client.reactions_add(channel=self._event.channel,
                name='ballot_box_with_check', timestamp=self._event.ts)

    def _reply(self, message, at_user=True):
        '''Reply to a command mention.'''
        if at_user:
            message = f"<@{self._event.user}> {message}"
        self._client.chat_postMessage(channel=self._event.channel,
                text=message,
                # start a new thread or continue the existing one
                thread_ts=self._event.get('thread_ts', self._event.ts))

    def _fail(self, message):
        self._reply(message)
        raise HandledError()

    @register('ping')
    def _ping(self, *_args):
        # Check Bugzilla connectivity
        try:
            if not self._bzapi.logged_in:
                raise Exception('Not logged in.')
        except Exception:
            # Swallow exception details and just report the failure
            self._fail('Cannot contact Bugzilla.')
        self._complete()

    @register('help')
    def _help(self, *_args):
        self._reply(HELP, at_user=False)

    @register('throw')
    def _throw(self, *_args):
        # undocumented
        self._complete()
        raise Exception(f'Throwing exception as requested by <@{self._event.user}>')


@report_errors
def process_event(config, socket_client, req):
    '''Handler for a Slack event.'''
    payload = DottedDict(req.payload)

    if req.type == 'events_api' and payload.event.type == 'app_mention':
        if payload.event.channel != config.channel:
            # Don't even acknowledge events outside our channel, to
            # avoid interfering with separate instances in other
            # channels.
            return

        # Acknowledge the event, as required by Slack.
        resp = SocketModeResponse(envelope_id=req.envelope_id)
        socket_client.send_socket_mode_response(resp)

        with Database(config) as db:
            if not db.add_event(payload.event.channel, payload.event.event_ts):
                # When we ignore some events, Slack can send us duplicate
                # retries.  Detect and ignore those after acknowledging.
                return

        CommandHandler(config, payload.event)()


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
