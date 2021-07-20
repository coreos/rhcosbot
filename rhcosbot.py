#!/usr/bin/python3
#
# Apache 2.0 license

import argparse
import bugzilla
from collections import OrderedDict
from dotted_dict import DottedDict
from functools import cached_property, reduce, wraps
import os
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
`backport <bz-url-or-id> <minimum-release>` - ensure there are backport bugs down to minimum-release
`bootimage list` - list upcoming bootimage bumps
`bootimage bug add <bz-url-or-id>` - add a bug and its backports to planned bootimage bumps
`bootimage bug ready <bz-url-or-id>` - mark a bug landed in plashet and waiting for bootimage
`release list` - list known releases
`ping` - check whether the bot is running properly
`help` - print this message

Bug statuses:
*NEW, ASSIGNED*
POST
_POST and ready for bootimage_
~MODIFIED, ON_QA, VERIFIED, CLOSED~
¿Other?

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


class Release:
    '''One release specification from the config.'''

    def __init__(self, config_struct):
        self.label = config_struct.label
        self.target = config_struct.bz_target
        self.aliases = config_struct.get('bz_target_aliases', [])

    def __repr__(self):
        return f'<{self.__class__.__name__} {self.label}>'

    def has_target(self, target):
        return target == self.target or target in self.aliases


class Releases(OrderedDict):
    '''Release specifications from the config, keyed by the label.'''

    @classmethod
    def from_config(cls, config):
        ret = cls()
        targets = set()
        for struct in config.releases:
            rel = Release(struct)
            ret[rel.label] = rel
            # Validate that there are no duplicate targets
            for target in [rel.target] + rel.aliases:
                if target in targets:
                    raise ValueError(f'Duplicate target version "{target}"')
                targets.add(target)
        return ret

    @property
    def current(self):
        '''Return the current release.'''
        return next(iter(self.values()))

    @property
    def previous(self):
        '''Return previous releases.'''
        ret = self.copy()
        ret.popitem(last=False)
        return ret

    def at_least(self, label):
        '''Return all releases >= the specified label, or all releases if
        no label is specified.'''
        if label is None:
            return self.copy()
        ret = self.__class__()
        for rel in self.values():
            ret[rel.label] = rel
            if rel.label == label:
                return ret
        raise KeyError(label)

    @cached_property
    def by_target(self):
        '''Return a map from target to Release.'''
        ret = {}
        for rel in self.values():
            ret[rel.target] = rel
            for alias in rel.aliases:
                ret[alias] = rel
        return ret


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


def register(*args, fast=False, complete=True):
    '''Decorator that registers the subcommand handled by a function.'''
    def decorator(f):
        f._command = tuple(args)
        f._fast = fast
        f._complete = complete
        return f
    return decorator


class CommandHandler(metaclass=Registry):
    '''Wrapper class to handle a single event in a thread.  Creates its own
    network clients for thread safety.'''

    BOOTIMAGE_WHITEBOARD = 'bootimage'
    # Can't use hyphens or underscores, since those count as a word boundary
    BOOTIMAGE_BUG_WHITEBOARD = 'bootimageNeeded'
    BOOTIMAGE_BUG_READY_WHITEBOARD = 'bootimageReady'

    # Some standard BZ fields that we usually want
    DEFAULT_FIELDS = [
        'cf_devel_whiteboard',
        'component',
        'product',
        'summary',
        'status',
        'target_release',
    ]

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
                @report_errors
                def wrapper(_config):
                    if not f._fast:
                        self._react('hourglass_flowing_sand')
                    try:
                        f(self, *words[count:])
                    except HandledError:
                        self._react('x')
                        raise
                    except Exception:
                        self._react('boom')
                        raise
                    finally:
                        if not f._fast:
                            self._client.reactions_remove(
                                channel=self._event.channel,
                                timestamp=self._event.ts,
                                name='hourglass_flowing_sand'
                            )
                    if f._complete:
                        self._react('ballot_box_with_check')
                # report_errors() requires the config to be the first argument
                threading.Thread(target=wrapper, name=f.__name__,
                        args=(self._config,)).start()
                return

        # Tried all possible subcommand lengths, found nothing in registry
        self._reply(f"I didn't understand that.  Try `<@{self._config.bot_id}> help`")
        self._react('x')

    def _react(self, name):
        '''Add an emoji to a command mention.'''
        self._client.reactions_add(channel=self._event.channel,
                name=name, timestamp=self._event.ts)

    def _reply(self, message, at_user=True):
        '''Reply to a command mention.'''
        if at_user:
            message = f"<@{self._event.user}> {message}"
        self._client.chat_postMessage(channel=self._event.channel,
                text=message,
                # start a new thread or continue the existing one
                thread_ts=self._event.get('thread_ts', self._event.ts),
                # disable Shodan link unfurls
                unfurl_links=False, unfurl_media=False)

    def _fail(self, message):
        self._reply(message)
        raise HandledError()

    def _getbug(self, desc, fields=[]):
        '''Query Bugzilla for a bug.  desc can be a bug number, or a string
        with a bug number, or a BZ URL with optional anchor.'''

        # Convert desc to integer
        if isinstance(desc, str):
            # Slack puts URLs inside <>.
            try:
                bz = int(desc.replace(self._config.bugzilla_bug_url, '', 1). \
                        split('#')[0]. \
                        strip(' <>'))
            except ValueError:
                self._fail("Invalid bug number.")
        else:
            bz = desc

        # Query Bugzilla
        fields = fields + self.DEFAULT_FIELDS
        try:
            bug = self._bzapi.getbug(bz, include_fields=fields)
        except IndexError:
            self._fail(f"Couldn't find bug {bz}.")

        # Basic validation that it's safe to operate on this bug
        if bug.product != self._config.bugzilla_product:
            self._fail(f'Bug {bz} has unexpected product "{escape(bug.product)}".')
        if bug.component != self._config.bugzilla_component:
            self._fail(f'Bug {bz} has unexpected component "{escape(bug.component)}".')

        return bug

    def _query(self, fields=[], whiteboard=None, extra={},
            default_component=True, **kwargs):
        '''Search Bugzilla.  kwargs are passed to build_query().  Arguments
        not supported by build_query can be passed in extra and will be
        applied to the query dict afterward.  Limit to configured product/
        component unless default_component is False.'''

        if default_component:
            kwargs.update({
                'product': self._config.bugzilla_product,
                'component': self._config.bugzilla_component,
            })
        query = self._bzapi.build_query(
            include_fields=fields + self.DEFAULT_FIELDS,
            **kwargs
        )
        query.update(extra)
        if whiteboard is not None:
            query.update({
                'f1': 'cf_devel_whiteboard',
                'o1': 'allwords',
                'v1': whiteboard,
            })
        return sorted(self._bzapi.query(query), key=lambda b: b.id)

    def _get_backports(self, bug, fields=[], min_ver=None):
        '''Follow the backport bug chain from the specified Bug, until we
        reach min_ver or run out of bugs or configured releases.  Return a
        list of Bugs from newest to oldest release, including the specified
        Bugzilla fields.  Fail if the specified BZ doesn't match the
        configured current release.'''

        # Check bug invariants
        bug_target = bug.target_release[0]
        if not self._config.releases.current.has_target(bug_target):
            self._fail(f'Bug {bug.id} has non-current target release "{escape(bug_target)}".')

        # Walk each backport version
        cur_bug = bug
        ret = []
        for rel in self._config.releases.at_least(min_ver).previous.values():
            # Check for an existing clone with this target release or
            # one of its aliases
            candidates = self._query(fields=fields, extra={
                'cf_clone_of': cur_bug.id,
            })
            candidates = [
                b for b in candidates
                if rel.has_target(b.target_release[0])
            ]
            if len(candidates) > 1:
                bzlist = ', '.join(str(b.id) for b in candidates)
                self._fail(f"Found multiple clones of bug {cur_bug.id} with target release {rel.label}: {bzlist}")
            if len(candidates) == 0:
                break
            cur_bug = candidates[0]
            ret.append(cur_bug)
        return ret

    def _get_bootimages(self, status='ASSIGNED', fields=[]):
        '''Get a map from release label to bootimage bump bug with the
        specified status.  Fail if any release has multiple bootimage bumps
        with that status.  Include the specified bug fields.'''

        bugs = self._query(fields=fields, status=status,
                whiteboard=self.BOOTIMAGE_WHITEBOARD)
        ret = {}
        for bug in bugs:
            try:
                rel = self._config.releases.by_target[bug.target_release[0]]
            except KeyError:
                # unknown target release; ignore
                continue
            if rel.label in ret:
                self._fail(f'Found multiple bootimage bumps for release {rel.label} with status {status}: {ret[rel.label].id}, {bug.id}.')
            ret[rel.label] = bug
        return ret

    def _bug_link(self, bug, text=None):
        '''Format a Bug into a Slack link.'''
        text = str(text) if text else bug.summary
        link = f'<{self._config.bugzilla_bug_url}{str(bug.id)}|{escape(text)}>'
        if bug.status in ('NEW', 'ASSIGNED'):
            return f'*{link}*'
        if bug.status == 'POST':
            if self.BOOTIMAGE_BUG_READY_WHITEBOARD in self._whiteboard(bug):
                return f'_{link}_'
            return link
        if bug.status in ('MODIFIED', 'ON_QA', 'VERIFIED', 'CLOSED'):
            return f'~{link}~'
        return f'¿{link}?'

    @staticmethod
    def _whiteboard(bug):
        '''Return the words in the dev whiteboard for the specified Bug.'''
        return bug.cf_devel_whiteboard.split()

    @register('backport')
    def _backport(self, *args):
        '''Ensure the existence of backport bugs for the specified BZ,
        in all releases >= the specified one.'''
        # Parse arguments
        try:
            desc, min_ver = args
        except ValueError:
            self._fail(f'Bad arguments; expect `bug minimum-release`.')

        # Fail if release is invalid or current
        if min_ver not in self._config.releases:
            self._fail(f'Unknown release "{escape(min_ver)}".')
        if min_ver == self._config.releases.current.label:
            self._fail(f"{escape(min_ver)} is the current release; can't backport.")

        # Look up the bug.  This validates the product and component.
        bug = self._getbug(desc, [
            'assigned_to',
            'groups',
            'severity',
            'version',
        ])
        if bug.severity == 'unspecified':
            # Eric-Paris-bot will unset the target version without a severity
            self._fail("Bug severity is not set; can't backport.")

        # Query existing backport bugs
        backports = self._get_backports(bug, min_ver=min_ver)

        # Query bootimages if needed
        need_bootimage = self.BOOTIMAGE_BUG_WHITEBOARD in self._whiteboard(bug)
        if need_bootimage:
            bootimages = self._get_bootimages()

        # First, do checks
        for rel in list(self._config.releases.at_least(min_ver).previous.values())[len(backports):]:
            if need_bootimage:
                if rel.label not in bootimages:
                    self._fail(f"Couldn't find bootimage for {rel.label}.")

        # Walk each backport version
        cur_bug = bug
        created_bugs = []
        all_bugs = []
        for rel in self._config.releases.at_least(min_ver).previous.values():
            if backports:
                # Have an existing bug
                cur_bug = backports.pop(0)
            else:
                # Make a new one
                depends = [cur_bug.id]
                if need_bootimage:
                    depends.append(bootimages[rel.label].id)
                info = self._bzapi.build_createbug(
                    product=bug.product,
                    component=bug.component,
                    version=bug.version,
                    summary=f'[{rel.label}] {bug.summary}',
                    description=f'Backport the fix for bug {bug.id} to {rel.label}.',
                    assigned_to=bug.assigned_to,
                    depends_on=depends,
                    groups=bug.groups,
                    severity=bug.severity,
                    status='ASSIGNED',
                    target_release=rel.target
                )
                info['cf_clone_of'] = cur_bug.id
                if need_bootimage:
                    info['cf_devel_whiteboard'] = self.BOOTIMAGE_BUG_WHITEBOARD
                bz = self._bzapi.createbug(info).id
                cur_bug = self._getbug(bz)
                created_bugs.append(self._bug_link(cur_bug, rel.label))
            all_bugs.append(self._bug_link(cur_bug, rel.label))

        created_bugs.reverse()
        all_bugs.reverse()
        message = ''
        if created_bugs:
            message += f'Created bugs: {", ".join(created_bugs)}\n'
        message += f'All backports: {", ".join(all_bugs)}'
        self._reply(message, at_user=False)

    @register('bootimage', 'list')
    def _bootimage_list(self, *args):
        '''List bootimage bump BZs.'''

        sections = (
            ('Planned bootimage bumps', 'ASSIGNED'),
            ('Pending bootimage bumps', 'POST'),
        )
        report = []
        for caption, status in sections:
            bootimages = self._get_bootimages(status=status)
            if not bootimages:
                continue
            report.append(f'*_{caption}_*:')
            for label, rel in reversed(self._config.releases.items()):
                try:
                    bootimage = bootimages[label]
                except KeyError:
                    # nothing for this release
                    continue
                # Find bugs attached to this bootimage bump.  We normally
                # refuse to create bootimage bugs outside our component, but
                # if they've been created manually, detect them anyway so
                # bugs don't get missed.
                bugs = self._query(whiteboard=self.BOOTIMAGE_BUG_WHITEBOARD,
                        dependson=[bootimage.id], default_component=False)
                report.append(self._bug_link(bootimage, label) + ':')
                found = False
                for bug in bugs:
                    if rel.has_target(bug.target_release[0]):
                        report.append('• ' + self._bug_link(bug))
                        found = True
                if not found:
                    report.append('_no bugs_')
        self._client.chat_postMessage(channel=self._event.channel,
                text='\n'.join(report), unfurl_links=False, unfurl_media=False)

    @register('bootimage', 'bug', 'add')
    def _bootimage_bug_add(self, *args):
        '''Add a bug and its backports to planned bootimage bumps.'''
        # Parse arguments
        try:
            desc = args[0]
        except ValueError:
            self._fail(f'Bad arguments; expect `bug`.')

        # Look up the bug.  This validates the product and component.
        bug = self._getbug(desc)

        # Get planned bootimage bumps
        bootimages = self._get_bootimages()

        # Get bug and its backports
        bugs = [bug] + self._get_backports(bug)

        # First, do checks
        for rel, cur_bug in zip(self._config.releases.values(), bugs):
            assert rel.has_target(cur_bug.target_release[0])
            if rel.label not in bootimages:
                self._fail(f"Couldn't find bootimage for {rel.label} for bug {cur_bug.id}.")
            if self.BOOTIMAGE_BUG_WHITEBOARD not in self._whiteboard(cur_bug):
                if cur_bug.status not in ('NEW', 'ASSIGNED', 'POST'):
                    self._fail(f'Refusing to add bug {cur_bug.id} in {cur_bug.status} to bootimage bump.')

        # Add to bootimage bumps; generate report
        added_bugs = []
        all_bugs = []
        for rel, cur_bug in zip(self._config.releases.values(), bugs):
            link = self._bug_link(cur_bug, rel.label)
            all_bugs.append(link)
            if self.BOOTIMAGE_BUG_WHITEBOARD not in self._whiteboard(cur_bug):
                bootimage = bootimages[rel.label]
                update = self._bzapi.build_update(
                    depends_on_add=[bootimage.id],
                )
                update['cf_devel_whiteboard'] = f'{cur_bug.cf_devel_whiteboard} {self.BOOTIMAGE_BUG_WHITEBOARD}'
                self._bzapi.update_bugs([cur_bug.id], update)
                added_bugs.append(link)

        # Show report
        added_bugs.reverse()
        all_bugs.reverse()
        message = ''
        if added_bugs:
            message += f'Added to bootimage: {", ".join(added_bugs)}\n'
        message += f'All bugs: {", ".join(all_bugs)}'
        self._reply(message, at_user=False)

    @register('bootimage', 'bug', 'ready')
    def _bootimage_bug_ready(self, *args):
        '''Mark a bug ready for its bootimage bump.'''
        # Parse arguments
        try:
            desc = args[0]
        except ValueError:
            self._fail(f'Bad arguments; expect `bug`.')

        # Look up the bug.  This validates the product and component.
        bug = self._getbug(desc)

        if self.BOOTIMAGE_BUG_WHITEBOARD not in self._whiteboard(bug):
            self._fail(f'Bug {bug.id} is not attached to a bootimage bump.')
        if bug.status not in ('NEW', 'ASSIGNED', 'POST'):
            self._fail(f'Refusing to mark bug {bug.id} ready from status {bug.status}.')
        if self.BOOTIMAGE_BUG_READY_WHITEBOARD not in self._whiteboard(bug):
            update = self._bzapi.build_update(
                status='POST',
                comment="This bug has been reported fixed in a new RHCOS build.  Do not move this bug to MODIFIED until the fix has landed in a new bootimage.",
            )
            update['cf_devel_whiteboard'] = f'{bug.cf_devel_whiteboard} {self.BOOTIMAGE_BUG_READY_WHITEBOARD}'
            self._bzapi.update_bugs([bug.id], update)

    @register('release', 'list', fast=True, complete=False)
    def _release_list(self, *args):
        report = []
        for rel in reversed(self._config.releases.values()):
            report.append(f'{rel.label}: *{rel.target}* {" ".join(rel.aliases)}')
        body = "\n".join(report)
        self._reply(f'Release: *default-target* other-targets\n{body}\n', at_user=False)

    @register('ping', fast=True)
    def _ping(self, *_args):
        # Check Bugzilla connectivity
        try:
            if not self._bzapi.logged_in:
                raise Exception('Not logged in.')
        except Exception:
            # Swallow exception details and just report the failure
            self._fail('Cannot contact Bugzilla.')

    @register('help', fast=True, complete=False)
    def _help(self, *_args):
        self._reply(HELP, at_user=False)

    @register('throw', fast=True, complete=False)
    def _throw(self, *_args):
        # undocumented
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
        config.releases = Releases.from_config(config)
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

    # Clean up database every hour
    while True:
        with db:
            db.prune_events()
        time.sleep(3600)


if __name__ == '__main__':
    main()
