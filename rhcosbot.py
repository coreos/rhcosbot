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
from slack_sdk.socket_mode import SocketModeClient
from slack_sdk.socket_mode.response import SocketModeResponse
import sqlite3
import time
import threading
import traceback
import yaml

ISSUE_LINK = 'https://github.com/coreos/rhcosbot/issues'
HELP = f'''
I understand these commands:
%commands%

Bug statuses:
*NEW, ASSIGNED*
POST
_POST and ready for bootimage_
~MODIFIED, ON_QA, VERIFIED, CLOSED~
¿Other?

Report problems <{ISSUE_LINK}|here>.
'''


bootimage_creation_lock = threading.Lock()


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
        if exc_type in (HandledError, Fail):
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


class Fail(Exception):
    '''An exception with a message that should be displayed to the user.'''
    pass


class Release:
    '''One release specification from the config.'''

    def __init__(self, config_struct):
        self.label = config_struct.label
        self.version = config_struct.bz_version
        self.target = config_struct.bz_target
        self.aliases = config_struct.get('bz_target_aliases', [])

    def __repr__(self):
        return f'<{self.__class__.__name__} {self.label}>'

    @property
    def targets(self):
        return [self.target] + self.aliases


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


class Bugzilla:
    '''Wrapper class for accessing Bugzilla.'''

    # Some standard BZ fields that we usually want
    DEFAULT_FIELDS = [
        'cf_devel_whiteboard',
        'component',
        'keywords',
        'product',
        'summary',
        'status',
        'target_release',
    ]

    BOOTIMAGE_WHITEBOARD = 'bootimage'
    # Can't use hyphens or underscores, since those count as a word boundary
    BOOTIMAGE_BUG_WHITEBOARD = 'bootimageNeeded'
    BOOTIMAGE_BUG_READY_WHITEBOARD = 'bootimageReady'

    def __init__(self, config):
        self.api = bugzilla.Bugzilla(config.bugzilla,
                api_key=config.bugzilla_key, force_rest=True)
        self._config = config

    def getbug(self, desc, fields=[]):
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
                raise Fail("Invalid bug number.")
        else:
            bz = desc

        # Query Bugzilla
        fields = fields + self.DEFAULT_FIELDS
        try:
            bug = self.api.getbug(bz, include_fields=fields)
        except IndexError:
            raise Fail(f"Couldn't find bug {bz}.")

        # Basic validation that it's safe to operate on this bug
        if bug.product != self._config.bugzilla_product:
            raise Fail(f'Bug {bz} has unexpected product "{escape(bug.product)}".')
        if bug.component != self._config.bugzilla_component:
            raise Fail(f'Bug {bz} has unexpected component "{escape(bug.component)}".')

        return bug

    def query(self, fields=[], whiteboard=None, extra={},
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
        query = self.api.build_query(
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
        return sorted(self.api.query(query), key=lambda b: b.id)

    def get_backports(self, bug, fields=[], min_ver=None):
        '''Follow the backport bug chain from the specified Bug, until we
        reach min_ver or run out of bugs or configured releases.  Return a
        list of Bugs from newest to oldest release, including the specified
        Bugzilla fields.  Fail if the specified BZ doesn't match the
        configured current release.'''

        # Check bug invariants
        bug_target = bug.target_release[0]
        if bug_target not in self._config.releases.current.targets:
            raise Fail(f'Bug {bug.id} targets release "{escape(bug_target)}" but latest release is {self._config.releases.current.target}.')

        # Walk each backport version
        cur_bug = bug
        ret = []
        for rel in self._config.releases.at_least(min_ver).previous.values():
            # Check for an existing clone with this target release or
            # one of its aliases
            candidates = self.query(
                target_release=rel.targets,
                fields=fields,
                extra={
                    'cf_clone_of': cur_bug.id,
                },
            )
            if len(candidates) > 1:
                bzlist = ', '.join(str(b.id) for b in candidates)
                raise Fail(f"Found multiple clones of bug {cur_bug.id} with target release {rel.label}: {bzlist}")
            if len(candidates) == 0:
                break
            cur_bug = candidates[0]
            ret.append(cur_bug)
        return ret

    def get_bootimages(self, status='ASSIGNED', fields=[]):
        '''Get a map from release label to bootimage bump bug with the
        specified status.  Fail if any release has multiple bootimage bumps
        with that status.  Include the specified bug fields.'''

        bugs = self.query(fields=fields, status=status,
                whiteboard=self.BOOTIMAGE_WHITEBOARD)
        ret = {}
        for bug in bugs:
            try:
                rel = self._config.releases.by_target[bug.target_release[0]]
            except KeyError:
                # unknown target release; ignore
                continue
            if rel.label in ret:
                raise Fail(f'Found multiple bootimage bumps for release {rel.label} with status {status}: {ret[rel.label].id}, {bug.id}.')
            ret[rel.label] = bug
        return ret

    def get_bootimage_bugs(self, bootimage, release, fields=[], ready=False,
            **kwargs):
        '''Find bugs attached to the specified bootimage bump and release,
        which must match.  We normally refuse to create bootimage bugs
        outside our component, but if they've been created manually, detect
        them anyway so bugs don't get missed.  If ready is True, only find
        bugs that are marked ready.'''
        whiteboard = self.BOOTIMAGE_BUG_WHITEBOARD
        if ready:
            whiteboard += ' ' + self.BOOTIMAGE_BUG_READY_WHITEBOARD
        return self.query(
            dependson=[bootimage.id],
            target_release=release.targets,
            fields=fields,
            whiteboard=whiteboard,
            default_component=False,
            **kwargs
        )

    @staticmethod
    def whiteboard(bug):
        '''Return the words in the dev whiteboard for the specified Bug.'''
        return bug.cf_devel_whiteboard.split()

    def create_bootimage(self, release, fields=[]):
        '''Create or look up a bootimage bug for the specified release and
        return a bug including the specified fields, and a boolean
        indicating whether the bootimage bug was newly created.'''
        # Lock to make sure multiple Slack commands don't race to create the
        # bug
        with bootimage_creation_lock:
            created = False
            # Double-check for the BZ under the creation lock
            bugs = self.query(
                status='ASSIGNED',
                whiteboard=self.BOOTIMAGE_WHITEBOARD,
                target_release=release.targets
            )
            if len(bugs) > 1:
                raise Fail(f'Found multiple existing bootimage bumps for release {release.label} with status ASSIGNED: {", ".join(str(b.id) for b in bugs)}')
            elif bugs:
                # Reuse existing bug
                bz = bugs[0].id
            else:
                # Create new bug
                desc = f'Tracker bug for bootimage bump in {release.label}.  This bug should block bugs which need a bootimage bump to fix.'
                # Find the most recent bump for this release, if any.
                # Use the one with the highest ID.
                previous = self.query(
                    status=['POST', 'MODIFIED', 'ON_QA', 'VERIFIED', 'RELEASE_PENDING', 'CLOSED'],
                    whiteboard=self.BOOTIMAGE_WHITEBOARD,
                    target_release=release.targets,
                )
                if previous:
                    previous_id = list(b.id for b in previous)[-1]
                    desc += f'\n\nThe previous bump was bug {previous_id}.'
                info = self.api.build_createbug(
                    product=self._config.bugzilla_product,
                    component=self._config.bugzilla_component,
                    version=release.version,
                    summary=f'[{release.label}] Bootimage bump tracker',
                    description=desc,
                    cc=self._config.get('bugzilla_cc', []),
                    assigned_to=self._config.bugzilla_assignee,
                    severity=self._config.get('bugzilla_severity', 'medium'),
                    status='ASSIGNED',
                    target_release=release.target,
                )
                info['cf_devel_whiteboard'] = self.BOOTIMAGE_WHITEBOARD
                if previous:
                    info['cf_clone_of'] = previous_id
                bz = self.api.createbug(info).id
                created = True
        return self.getbug(bz, fields=fields), created

    def ensure_bootimage_bug_allowed(self, bug):
        '''Raise Fail if the bug must not be added to a bootimage bump.'''
        deny_keywords = self._config.get('bootimage_deny_keywords', [])
        kw = set(deny_keywords) & set(bug.keywords)
        if kw:
            raise Fail(f'By policy, this bug cannot be added to a bootimage bump because of keywords: *{escape(", ".join(kw))}*')

    def update_bootimage_bug_status(self, bootimage_status, bootimage_bug_status,
            new_bootimage_bug_status, comment, ready=False):
        '''Find all bootimage bugs in status bootimage_bug_status (list) and
        associated with a bootimage in status bootimage_status (singular),
        then move them to new_bootimage_bug_status with the specified comment,
        which supports the format fields "bootimage" (bootimage BZ ID) and
        "status" (bootimage BZ status).  If ready is True, modify only
        bootimage bugs which have been marked ready.'''
        bootimages = self.get_bootimages(status=bootimage_status)
        for label, rel in self._config.releases.items():
            try:
                bootimage = bootimages[label]
            except KeyError:
                continue
            bugs = self.get_bootimage_bugs(bootimage, rel,
                    status=bootimage_bug_status, ready=ready)
            if not bugs:
                continue
            update = self.api.build_update(
                status=new_bootimage_bug_status,
                comment=comment.format(
                    bootimage=bootimage.id,
                    status=bootimage.status
                ),
            )
            self.api.update_bugs([b.id for b in bugs], update)


def report_errors(f):
    '''Decorator that sends exceptions to an administrator via Slack DM
    and then swallows them.  The first argument of the function must be
    the config.'''
    import json, requests, socket, urllib.error
    @wraps(f)
    def wrapper(config, *args, **kwargs):
        def send(message):
            try:
                client = WebClient(token=config.slack_token)
                channel = client.conversations_open(users=[config.error_notification])['channel']['id']
                client.chat_postMessage(channel=channel, text=message)
            except Exception:
                traceback.print_exc()
        try:
            return f(config, *args, **kwargs)
        except Fail as e:
            # Nothing else caught this; just report the error string.
            send(str(e))
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
        except Exception:
            send(f'Caught exception:\n```\n{traceback.format_exc()}```')
    return wrapper


class Registry(type):
    '''Metaclass that creates a dict of functions registered with the
    register decorator.'''

    def __new__(cls, name, bases, attrs):
        cls = super().__new__(cls, name, bases, attrs)
        registry = []
        for f in attrs.values():
            command = getattr(f, 'command', None)
            if command is not None:
                registry.append((command, f))
        registry.sort(key=lambda t: t[1].doc_order)
        cls._registry = OrderedDict(registry)
        return cls


def register(command, args=(), doc=None, fast=False, complete=True):
    '''Decorator that registers the subcommand handled by a function.'''
    def decorator(f):
        f.command = command
        f.args = args
        f.doc = doc
        f.doc_order = time.time()  # hack alert!
        f.fast = fast
        f.complete = complete
        return f
    return decorator


class CommandHandler(metaclass=Registry):
    '''Wrapper class to handle a single event in a thread.  Creates its own
    network clients for thread safety.'''

    def __init__(self, config, event):
        self._config = config
        self._event = event
        self._client = WebClient(token=config.slack_token)
        self._bz = Bugzilla(config)
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
                    if not f.fast:
                        self._react('hourglass_flowing_sand')
                    try:
                        args = words[count:]
                        if len(args) != len(f.args):
                            if f.args:
                                argdesc = ' '.join(f'<{a}>' for a in f.args)
                                raise Fail(f'Bad arguments; expect `{argdesc}`.')
                            else:
                                raise Fail('This command takes no arguments.')
                        f(self, *args)
                    except Fail as e:
                        self._react('x')
                        self._reply(str(e))
                        # convert to HandledError to indicate that we've
                        # displayed this message
                        raise HandledError()
                    except Exception:
                        self._react('boom')
                        raise
                    finally:
                        if not f.fast:
                            self._client.reactions_remove(
                                channel=self._event.channel,
                                timestamp=self._event.ts,
                                name='hourglass_flowing_sand'
                            )
                    if f.complete:
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

    def _bug_link(self, bug, text=None):
        '''Format a Bug into a Slack link.'''
        text = str(text) if text else bug.summary
        link = f'<{self._config.bugzilla_bug_url}{str(bug.id)}|{escape(text)}>'
        if bug.status in ('NEW', 'ASSIGNED'):
            return f'*{link}*'
        if bug.status == 'POST':
            if self._bz.BOOTIMAGE_BUG_READY_WHITEBOARD in self._bz.whiteboard(bug):
                return f'_{link}_'
            return link
        if bug.status in ('MODIFIED', 'ON_QA', 'VERIFIED', 'CLOSED'):
            return f'~{link}~'
        return f'¿{link}?'

    @register(('backport',), ('bz-url-or-id', 'minimum-release'),
            doc='ensure there are backport bugs down to minimum-release')
    def _backport(self, desc, min_ver):
        '''Ensure the existence of backport bugs for the specified BZ,
        in all releases >= the specified one.'''
        # Fail if release is invalid or current
        if min_ver not in self._config.releases:
            raise Fail(f'Unknown release "{escape(min_ver)}".')
        if min_ver == self._config.releases.current.label:
            raise Fail(f"{escape(min_ver)} is the current release; can't backport.")

        # Look up the bug.  This validates the product and component.
        bug = self._bz.getbug(desc, [
            'assigned_to',
            'groups',
            'severity',
            'version',
        ])
        if bug.severity == 'unspecified':
            # Eric-Paris-bot will unset the target version without a severity
            raise Fail("Bug severity is not set; can't backport.")

        # Query existing backport bugs
        backports = self._bz.get_backports(bug, min_ver=min_ver)

        # Query bootimages if needed
        need_bootimage = self._bz.BOOTIMAGE_BUG_WHITEBOARD in self._bz.whiteboard(bug)
        if need_bootimage:
            self._bz.ensure_bootimage_bug_allowed(bug)
            bootimages = self._bz.get_bootimages(fields=['blocks'])

        # First, do checks
        created_bootimages = []
        for rel in list(self._config.releases.at_least(min_ver).previous.values())[len(backports):]:
            if need_bootimage:
                if rel.label not in bootimages:
                    bootimages[rel.label], created = self._bz.create_bootimage(rel, fields=['blocks'])
                    if created:
                        created_bootimages.append(self._bug_link(bootimages[rel.label], rel.label))
        groups = bug.groups
        allow_groups = self._config.get('backport_allow_groups', [])
        if allow_groups:
            groups = list(set(groups) & set(allow_groups))
        if bug.groups and not groups:
            raise Fail("Cannot add any of the bug's groups to new clones, and refusing to create a public bug.")

        # Walk each backport version
        cur_bug = bug
        later_rel = self._config.releases.current
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
                info = self._bz.api.build_createbug(
                    product=bug.product,
                    component=bug.component,
                    version=bug.version,
                    summary=f'[{rel.label}] {bug.summary}',
                    description=f'Backport the fix for bug {bug.id} to {rel.label}.',
                    assigned_to=bug.assigned_to,
                    keywords=bug.keywords,
                    depends_on=depends,
                    groups=groups,
                    severity=bug.severity,
                    status='ASSIGNED',
                    target_release=rel.target
                )
                info['cf_clone_of'] = cur_bug.id
                if need_bootimage:
                    info['cf_devel_whiteboard'] = self._bz.BOOTIMAGE_BUG_WHITEBOARD
                bz = self._bz.api.createbug(info).id
                cur_bug = self._bz.getbug(bz)
                created_bugs.append(self._bug_link(cur_bug, rel.label))
                if need_bootimage:
                    # Ensure this bootimage bump is blocked by the one for
                    # the more recent release.  Thus we dynamically track
                    # bootimage dependencies rather than imposing a fixed
                    # relationship between bumps in adjacent releases.  For
                    # example, a bump for 4.6 may coalesce the contents of
                    # two 4.7 bumps.
                    if bootimages[rel.label].id not in bootimages[later_rel.label].blocks:
                        info = self._bz.api.build_update(
                            blocks_add=[bootimages[rel.label].id],
                        )
                        self._bz.api.update_bugs([bootimages[later_rel.label].id], info)
            all_bugs.append(self._bug_link(cur_bug, rel.label))
            later_rel = rel

        created_bugs.reverse()
        all_bugs.reverse()
        message = ''
        if created_bootimages:
            message += f'Created bootimage bugs: {", ".join(created_bootimages)}\n'
        if created_bugs:
            message += f'Created bugs: {", ".join(created_bugs)}\n'
        message += f'All backports: {", ".join(all_bugs)}'
        self._reply(message, at_user=False)

    @register(('bootimage', 'create'), ('release',),
            doc='create bootimage bump (usually done automatically as needed)')
    def _bootimage_create(self, label):
        try:
            rel = self._config.releases[label]
        except KeyError:
            raise Fail(f'Unknown release "{escape(label)}".')
        bug, created = self._bz.create_bootimage(rel)
        link = self._bug_link(bug, rel.label)
        self._reply(f'{"Created" if created else "Existing"} bootimage bug: {link}', at_user=False)

    @register(('bootimage', 'list'), doc='list upcoming bootimage bumps')
    def _bootimage_list(self):
        '''List bootimage bump BZs.'''

        sections = (
            ('Planned bootimage bumps', 'ASSIGNED'),
            ('Pending bootimage bumps', 'POST'),
        )
        report = []
        for caption, status in sections:
            bootimages = self._bz.get_bootimages(status=status)
            if not bootimages:
                continue
            report.append(f'\n*_{caption}_*:')
            for label, rel in self._config.releases.items():
                try:
                    bootimage = bootimages[label]
                except KeyError:
                    # nothing for this release
                    continue
                bugs = self._bz.get_bootimage_bugs(bootimage, rel)
                report.append('\n*For* ' + self._bug_link(bootimage, label) + ':')
                for bug in bugs:
                    report.append('• ' + self._bug_link(bug))
                if not bugs:
                    report.append('_no bugs_')
        self._reply('\n'.join(report), at_user=False)

    @register(('bootimage', 'bug', 'add'), ('bz-url-or-id',),
            doc='add a bug and its backports to planned bootimage bumps')
    def _bootimage_bug_add(self, desc):
        '''Add a bug and its backports to planned bootimage bumps.'''
        # Look up the bug.  This validates the product and component.
        bug = self._bz.getbug(desc)
        self._bz.ensure_bootimage_bug_allowed(bug)

        # Get planned bootimage bumps
        bootimages = self._bz.get_bootimages(fields=['blocks'])

        # Get bug and its backports
        bugs = [bug] + self._bz.get_backports(bug)

        # First, do checks
        created_bootimages = []
        for rel, cur_bug in zip(self._config.releases.values(), bugs):
            assert cur_bug.target_release[0] in rel.targets
            if rel.label not in bootimages:
                bootimages[rel.label], created = self._bz.create_bootimage(rel, fields=['blocks'])
                if created:
                    created_bootimages.append(self._bug_link(bootimages[rel.label], rel.label))
            if self._bz.BOOTIMAGE_BUG_WHITEBOARD not in self._bz.whiteboard(cur_bug):
                if cur_bug.status not in ('NEW', 'ASSIGNED', 'POST'):
                    raise Fail(f'Refusing to add bug {cur_bug.id} in {cur_bug.status} to bootimage bump.')

        # Add to bootimage bumps; generate report
        later_rel = None
        added_bugs = []
        all_bugs = []
        for rel, cur_bug in zip(self._config.releases.values(), bugs):
            link = self._bug_link(cur_bug, rel.label)
            all_bugs.append(link)
            if self._bz.BOOTIMAGE_BUG_WHITEBOARD not in self._bz.whiteboard(cur_bug):
                bootimage = bootimages[rel.label]
                update = self._bz.api.build_update(
                    depends_on_add=[bootimage.id],
                )
                update['cf_devel_whiteboard'] = f'{cur_bug.cf_devel_whiteboard} {self._bz.BOOTIMAGE_BUG_WHITEBOARD}'
                self._bz.api.update_bugs([cur_bug.id], update)
                added_bugs.append(link)
                if later_rel is not None:
                    # Ensure this bootimage bump is blocked by the one for
                    # the more recent release.  Thus we dynamically track
                    # bootimage dependencies rather than imposing a fixed
                    # relationship between bumps in adjacent releases.  For
                    # example, a bump for 4.6 may coalesce the contents of
                    # two 4.7 bumps.
                    if bootimages[rel.label].id not in bootimages[later_rel.label].blocks:
                        info = self._bz.api.build_update(
                            blocks_add=[bootimages[rel.label].id],
                        )
                        self._bz.api.update_bugs([bootimages[later_rel.label].id], info)
            later_rel = rel

        # Show report
        added_bugs.reverse()
        all_bugs.reverse()
        message = ''
        if created_bootimages:
            message += f'Created bootimage bugs: {", ".join(created_bootimages)}\n'
        if added_bugs:
            message += f'Added to bootimage: {", ".join(added_bugs)}\n'
        message += f'All bugs: {", ".join(all_bugs)}'
        self._reply(message, at_user=False)

    @register(('bootimage', 'bug', 'ready'), ('bz-url-or-id',),
            doc='mark a bug landed in plashet and waiting for bootimage')
    def _bootimage_bug_ready(self, desc):
        '''Mark a bug ready for its bootimage bump.'''
        # Look up the bug.  This validates the product and component.
        bug = self._bz.getbug(desc)
        self._bz.ensure_bootimage_bug_allowed(bug)

        if self._bz.BOOTIMAGE_BUG_WHITEBOARD not in self._bz.whiteboard(bug):
            raise Fail(f'Bug {bug.id} is not attached to a bootimage bump.')
        if bug.status not in ('NEW', 'ASSIGNED', 'POST'):
            raise Fail(f'Refusing to mark bug {bug.id} ready from status {bug.status}.')
        if self._bz.BOOTIMAGE_BUG_READY_WHITEBOARD not in self._bz.whiteboard(bug):
            update = self._bz.api.build_update(
                status='POST',
                comment="This bug has been reported fixed in a new RHCOS build.  Do not move this bug to MODIFIED until the fix has landed in a new bootimage.",
            )
            update['cf_devel_whiteboard'] = f'{bug.cf_devel_whiteboard} {self._bz.BOOTIMAGE_BUG_READY_WHITEBOARD}'
            self._bz.api.update_bugs([bug.id], update)

    @register(('bootimage', 'bug', 'list'),
            doc='list bugs on upcoming bootimage bumps')
    def _bootimage_bug_list(self):
        sections = (
            ('Planned bootimage bumps', 'ASSIGNED'),
            ('Pending bootimage bumps', 'POST'),
        )
        report = []
        for caption, status in sections:
            bootimages = self._bz.get_bootimages(status=status)
            progenitors = {} # progenitor bug ID -> Bug
            groups = {} # progenitor bug ID -> [bug links]
            canonical = {} # backport bug ID -> progenitor bug ID
            for label, rel in self._config.releases.items():
                try:
                    bootimage = bootimages[label]
                except KeyError:
                    # nothing for this release
                    continue
                bugs = self._bz.get_bootimage_bugs(bootimage, rel,
                        fields=['cf_clone_of'])
                for bug in bugs:
                    # Find the progenitor from this bug's parent.  Maybe
                    # there is none, and we're the progenitor.
                    progenitor = canonical.get(bug.cf_clone_of, bug.id)
                    # Add the next link in the ancestry chain
                    canonical[bug.id] = progenitor
                    # If we're the progenitor, record bug details
                    progenitors.setdefault(progenitor, bug)
                    # Associate this bug's link with the progenitor
                    groups.setdefault(progenitor, []).append(
                        self._bug_link(bug, rel.label)
                    )
            if progenitors:
                report.append(f'\n*_{caption}_*:')
                for bz, bug in sorted(progenitors.items()):
                    report.append(f'• {escape(bug.summary)} [{", ".join(groups[bz])}]')
        self._reply('\n'.join(report), at_user=False)

    @register(('release', 'list'), doc='list known releases',
            fast=True, complete=False)
    def _release_list(self):
        report = []
        for rel in reversed(self._config.releases.values()):
            report.append(f'{rel.label}: *{rel.target}* {" ".join(rel.aliases)}')
        body = "\n".join(report)
        self._reply(f'Release: *default-target* other-targets\n{body}\n', at_user=False)

    @register(('ping',), doc='check whether the bot is running properly',
            fast=True)
    def _ping(self):
        # Check Bugzilla connectivity
        try:
            if not self._bz.api.logged_in:
                raise Exception('Not logged in.')
        except Exception:
            # Swallow exception details and just report the failure
            raise Fail('Cannot contact Bugzilla.')

    @register(('help',), doc='print this message', fast=True, complete=False)
    def _help(self):
        commands = []
        for command, f in self._registry.items():
            if f.doc is not None:
                commands.append('`{}{}{}` - {}'.format(
                    ' '.join(command),
                    ' ' if f.args else '',
                    ' '.join((f'<{a}>' for a in f.args)),
                    f.doc
                ))
        self._reply(HELP.replace('%commands%', '\n'.join(commands)),
                at_user=False)

    @register(('throw',), fast=True, complete=False)
    def _throw(self):
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


@report_errors
def periodic(config, db, bz):
    '''Run periodic tasks.'''

    # Prune database
    with db:
        db.prune_events()

    # Find bugs in state MODIFIED or later which are attached to bootimage
    # bumps in POST or earlier, and move the bugs back to POST.
    for status in ('ASSIGNED', 'POST'):
        bz.update_bootimage_bug_status(
            status,
            ['MODIFIED', 'ON_QA', 'VERIFIED', 'CLOSED'],
            'POST',
            'The fix for this bug will not be delivered to customers until it lands in an updated bootimage.  That process is tracked in bug {bootimage}, which is in state {status}.  Moving this bug back to POST.',
        )

    # Find POST+ready bugs which are attached to bootimage bumps in MODIFIED
    # or ON_QA, and move them to MODIFIED.
    for status in ('MODIFIED', 'ON_QA'):
        bz.update_bootimage_bug_status(
            status,
            ['POST'],
            'MODIFIED',
            'The fix for this bug has landed in a bootimage bump, as tracked in bug {bootimage} (now in status {status}).  Moving this bug to MODIFIED.',
            ready=True,
        )


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
    bz = Bugzilla(config)
    if not bz.api.logged_in:
        raise Exception('Did not authenticate')
    db = Database(config)

    # Start socket-mode listener in the background
    socket_client = SocketModeClient(app_token=config.slack_app_token,
            web_client=WebClient(token=config.slack_token))
    socket_client.socket_mode_request_listeners.append(
            lambda socket_client, req: process_event(config, socket_client, req))
    socket_client.connect()

    # Run periodic tasks
    while True:
        periodic(config, db, bz)
        time.sleep(config.bugzilla_poll_interval)


if __name__ == '__main__':
    main()
