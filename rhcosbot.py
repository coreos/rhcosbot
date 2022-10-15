#!/usr/bin/python3 -u
#
# Apache 2.0 license

import argparse
from collections import OrderedDict
from dotted_dict import DottedDict
from functools import cached_property, reduce, wraps
import itertools
from jira import JIRA, JIRAError
from jira.resources import Issue as JIRAIssue
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

Issue statuses:
:jira-1992: *New, ASSIGNED*
:branch: POST
:test_tube: POST &amp; in RHCOS build &amp; awaiting verification
:large_green_circle: _POST &amp; in RHCOS build &amp; verified_
:checkyes: ~MODIFIED, ON_QA, Verified, Closed~
:thinking_face: ¿Other?

Report problems <{ISSUE_LINK}|here>.
'''


tracker_creation_lock = threading.Lock()


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
        self.affects_version = config_struct.jira_affects_version
        self.target_version = config_struct.jira_target_version
        self.target_version_aliases = config_struct.get('jira_target_version_aliases', [])

    def __repr__(self):
        return f'<{self.__class__.__name__} {self.label}>'

    @property
    def target_versions(self):
        return [self.target_version] + self.target_version_aliases


class Releases(OrderedDict):
    '''Release specifications from the config, keyed by the label.'''

    @classmethod
    def from_config(cls, config):
        ret = cls()
        target_vers = set()
        for struct in config.releases:
            rel = Release(struct)
            ret[rel.label] = rel
            # Validate that there are no duplicate target versions
            for target_ver in rel.target_versions:
                if target_ver in target_vers:
                    raise ValueError(f'Duplicate target version "{target_ver}"')
                target_vers.add(target_ver)
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
    def by_target_version(self):
        '''Return a map from target version to Release.'''
        ret = {}
        for rel in self.values():
            ret[rel.target_version] = rel
            for alias in rel.target_version_aliases:
                ret[alias] = rel
        return ret


class Jira:
    '''Wrapper class for accessing Jira.'''

    # Some standard issue fields that we usually want
    DEFAULT_FIELDS = [
        'components',
        'issuelinks',
        'labels',
        'project',
        'summary',
        'status',
        'target_versions',
    ]

    BOOTIMAGE_TRACKER_LABEL = 'rhcos-bootimage-tracker'
    BOOTIMAGE_ISSUE_LABEL = 'rhcos-bootimage-needed'
    BOOTIMAGE_ISSUE_BUILT_LABEL = 'rhcos-image-built'
    BOOTIMAGE_ISSUE_VERIFIED_LABEL = 'verified'

    def __init__(self, config):
        self.api = self.connect(config)
        self._config = config

    @staticmethod
    def connect(config):
        '''Low-level method to return a JIRA API object.'''
        return JIRA(
            config.jira, token_auth=config.jira_token,
            default_batch_sizes={
                JIRAIssue: 20,
            }
        )

    @cached_property
    def _field_map(self):
        return {
            # "versions" is ambiguous, so rename to something more specific
            'affects_versions': 'versions',
            # Jira custom fields
            'severity': self._config.fields['Severity'],
            'target_versions': self._config.fields['Target Version'],
        }

    def field(self, name):
        return self._field_map.get(name, name)

    def _patch_issue(self, issue):
        # Replace custom fields with convenience names
        for k, v in self._field_map.items():
            if hasattr(issue.fields, v):
                setattr(issue.fields, k, getattr(issue.fields, v))
                delattr(issue.fields, v)
        # Add convenience fields for issue links
        for name in 'blocks', 'blocked_by', 'clones', 'cloned_by':
            setattr(issue, name, [])
        for link in issue.fields.issuelinks:
            if link.type.name == 'Blocks' and hasattr(link, 'inwardIssue'):
                issue.blocked_by.append(link.inwardIssue.id)
            if link.type.name == 'Blocks' and hasattr(link, 'outwardIssue'):
                issue.blocks.append(link.outwardIssue.id)
            if link.type.name == 'Cloners' and hasattr(link, 'inwardIssue'):
                issue.cloned_by.append(link.inwardIssue.id)
            if link.type.name == 'Cloners' and hasattr(link, 'outwardIssue'):
                issue.clones.append(link.outwardIssue.id)

    def issue(self, desc, fields=[]):
        '''Query Jira for an issue.  desc can be an issue number, or an issue
        key, or an issue URL with optional query string.'''

        if isinstance(desc, str):
            # Slack puts URLs inside <>.
            desc = desc.replace(self._config.jira_issue_url, '', 1). \
                    split('?')[0]. \
                    strip(' <>')

        # Query Jira
        fields = fields + self.DEFAULT_FIELDS
        try:
            issue = self.api.issue(desc, fields=[self.field(f) for f in fields])
        except JIRAError as e:
            if e.status_code == 404:
                raise Fail(f"Couldn't find issue {desc}.")
            raise
        self._patch_issue(issue)

        # Basic validation that it's safe to operate on this issue
        if issue.fields.project.key != self._config.jira_project_key:
            raise Fail(f'Issue {desc} has unexpected project "{escape(issue.fields.project.key)}".')
        if self._config.jira_component not in [c.name for c in issue.fields.components]:
            components_str = ", ".join(f'"{c.name}"' for c in issue.fields.components) or "<none>"
            raise Fail(f'Issue {desc} has unexpected component {escape(components_str)}.')

        return issue

    def search_issues(self, *terms, contains={}, clones=None,
            cloned_by=None, blocks=None, blocked_by=None, fields=[],
            default_component=True):
        '''Search Jira.  Terms are joined with ANDs.  contains gives allowed
        values for the specified fields.  Limit to configured project/
        component unless default_component is False.'''
        terms = list(terms)
        if default_component:
            terms.extend([
                f'project = "{self._config.jira_project_key}"',
                f'component = "{self._config.jira_component}"',
            ])
        for field, candidates in contains.items():
            if field == 'target_versions':
                # custom field ID doesn't work
                field = '"Target Version"'
            vals = ','.join(f'"{v}"' for v in candidates)
            terms.append(f'{field} in ({vals})')
        field_map = [
            # search looks outward from the specified issue, so we need to
            # reverse the direction
            (clones, 'is cloned by'),
            (cloned_by, 'clones'),
            (blocks, 'is blocked by'),
            (blocked_by, 'blocks'),
        ]
        for key, link_type in field_map:
            if key is not None:
                terms.append(f'issue IN linkedIssues({key}, "{link_type}")')
        # IDs are not sequential (!) so have the server sort by creation date
        query = ' AND '.join(f'({t})' for t in terms) + ' ORDER BY created ASC'
        if self._config.get('jira_log_searches', False):
            print(query)
        issues = self.api.search_issues(
            query,
            fields=[self.field(f) for f in (fields + self.DEFAULT_FIELDS)],
            maxResults=False,
        )
        for issue in issues:
            self._patch_issue(issue)
        return issues

    def create_issue_links(self, issue, blocks=[], blocked_by=[],
            clones=[], cloned_by=[]):
        '''Link issues.  All arguments must be keys, not IDs.'''
        for other in blocks:
            self.api.create_issue_link('blocks', issue, other)
        for other in blocked_by:
            self.api.create_issue_link('is blocked by', issue, other)
        for other in clones:
            self.api.create_issue_link('clones', issue, other)
        for other in cloned_by:
            self.api.create_issue_link('is cloned by', issue, other)

    def get_backports(self, issue, fields=[], min_ver=None):
        '''Follow the backport issue chain from the specified Issue, until we
        reach min_ver or run out of issues or configured releases.  Return a
        list of Issues from newest to oldest release, including the specified
        Jira fields.  Fail if the specified issue doesn't match the
        configured current release.'''

        # Check issue invariants
        if issue.fields.target_versions is None:
            raise Fail(f'{issue.key} has no target version; expected latest release {self._config.releases.current.target_version}.')
        issue_target = issue.fields.target_versions[0]
        if issue_target.name not in self._config.releases.current.target_versions:
            raise Fail(f'{issue.key} targets release "{escape(issue_target.name)}" but latest release is {self._config.releases.current.target_version}.')

        # Walk each backport version
        cur_issue = issue
        ret = []
        for rel in self._config.releases.at_least(min_ver).previous.values():
            # Check for an existing clone with this target version or
            # one of its aliases
            candidates = self.search_issues(
                clones=cur_issue.id,
                contains={
                    'target_versions': rel.target_versions,
                },
                fields=fields,
            )
            if len(candidates) > 1:
                keylist = ', '.join(str(b.key) for b in candidates)
                raise Fail(f"Found multiple clones of {cur_issue.key} with target version {rel.label}: {keylist}")
            if len(candidates) == 0:
                break
            cur_issue = candidates[0]
            ret.append(cur_issue)
        return ret

    def get_bootimage_trackers(self, status='ASSIGNED', fields=[]):
        '''Get a map from release label to bootimage tracker issue with the
        specified status.  Fail if any release has multiple bootimage trackers
        with that status.  Include the specified issue fields.'''

        issues = self.search_issues(
            f'status = "{status}"',
            f'labels = {self.BOOTIMAGE_TRACKER_LABEL}',
            fields=fields,
        )
        ret = {}
        for issue in issues:
            try:
                rel = self._config.releases.by_target_version[issue.fields.target_versions[0].name]
            except KeyError:
                # unknown target version; ignore
                continue
            if rel.label in ret:
                raise Fail(f'Found multiple bootimage trackers for release {rel.label} with status {status}: {ret[rel.label].key}, {issue.key}.')
            ret[rel.label] = issue
        return ret

    def get_bootimage_issues(self, tracker, release, status=[], fields=[],
            built=False):
        '''Find issues attached to the specified bootimage tracker and release,
        which must match.  We normally refuse to create bootimage issues
        outside our component, but if they've been created manually, detect
        them anyway so issues don't get missed.  If status is specified,
        returned issues must have one of the specified statuses.  If built
        is True, only find issues that are marked built.'''
        args = [f'labels = {self.BOOTIMAGE_ISSUE_LABEL}']
        if built:
            args.append(f'labels = {self.BOOTIMAGE_ISSUE_BUILT_LABEL}')
        contains = {
            'target_versions': release.target_versions,
        }
        if status:
            contains['status'] = status
        return self.search_issues(
            *args,
            contains=contains,
            blocked_by=tracker.id,
            fields=fields,
            default_component=False
        )

    def create_bootimage_tracker(self, release, fields=[]):
        '''Create or look up a bootimage tracker for the specified release and
        return an issue including the specified fields, and a boolean
        indicating whether the tracker was newly created.'''
        # Lock to make sure multiple Slack commands don't race to create the
        # issue
        with tracker_creation_lock:
            # Double-check for the tracker under the creation lock
            issues = self.search_issues(
                f'status = ASSIGNED',
                f'labels = {self.BOOTIMAGE_TRACKER_LABEL}',
                contains={
                    'target_versions': release.target_versions,
                },
                fields=fields
            )
            if len(issues) > 1:
                raise Fail(f'Found multiple existing bootimage trackers for release {release.label} with status ASSIGNED: {", ".join(str(i.key) for i in issues)}')
            elif issues:
                # Reuse existing issue
                return issues[0], False
            else:
                # Create new issue
                desc = f'Tracker issue for bootimage bump in {release.label}.  This issue should block issues which need a bootimage bump to fix.'
                # Find the most recent bump for this release, if any.
                # Use the one with the highest ID.
                previous = self.search_issues(
                    f'labels = {self.BOOTIMAGE_TRACKER_LABEL}',
                    contains={
                        'status': ['POST', 'MODIFIED', 'ON_QA', 'Verified', 'Release Pending', 'Closed'],
                        'target_versions': release.target_versions,
                    },
                )
                if previous:
                    previous = previous[-1]
                    desc += f'\n\nThe previous bump was {previous.key}.'
                issue = self.api.create_issue(fields={
                    self.field('issuetype'): 'Bug',
                    self.field('project'): self._config.jira_project_key,
                    self.field('components'): [{'name': self._config.jira_component}],
                    self.field('affects_versions'): [{'name': release.affects_version}],
                    self.field('summary'): f'[{release.label}] Bootimage bump tracker',
                    self.field('description'): desc,
                    self.field('severity'): {'value': self._config.get('jira_severity', 'Moderate')},
                    self.field('target_versions'): [{'name': release.target_version}],
                    self.field('labels'): [self.BOOTIMAGE_TRACKER_LABEL],
                })
                for watcher in self._config.get('jira_watchers', []):
                    self.api.add_watcher(issue.id, watcher)
                self.api.assign_issue(issue.id, self._config.jira_assignee)
                self.api.transition_issue(issue.id, 'ASSIGNED')
                if previous:
                    self.create_issue_links(issue.key, clones=[previous.key])
                return self.issue(issue.id, fields=fields), True

    def ensure_bootimage_issue_allowed(self, issue):
        '''Raise Fail if the issue must not be added to a bootimage tracker.'''
        deny_labels = self._config.get('bootimage_deny_labels', [])
        kw = set(deny_labels) & set(issue.fields.labels)
        if kw:
            raise Fail(f'By policy, this issue cannot be added to a bootimage tracker because of labels: *{escape(", ".join(kw))}*')

    def update_bootimage_issue_status(self, bootimage_tracker_status,
            bootimage_issue_status, new_bootimage_issue_status, comment,
            built=False):
        '''Find all bootimage issues in status bootimage_issue_status (list)
        and associated with a bootimage tracker in status
        bootimage_tracker_status (singular), then move them to
        new_bootimage_issue_status with the specified comment, which
        supports the format fields "tracker" (bootimage tracker key) and
        "status" (bootimage tracker status).  If built is True, modify only
        bootimage issues which have been marked built.'''
        trackers = self.get_bootimage_trackers(status=bootimage_tracker_status)
        for label, rel in self._config.releases.items():
            try:
                tracker = trackers[label]
            except KeyError:
                continue
            issues = self.get_bootimage_issues(tracker, rel,
                    status=bootimage_issue_status, built=built)
            for issue in issues:
                # comment argument doesn't seem to work for transitions that
                # don't require one
                self.api.transition_issue(issue.id, new_bootimage_issue_status)
                self.api.add_comment(issue.id, comment.format(
                    tracker=tracker.key,
                    status=tracker.fields.status.name
                ))


def report_errors(f):
    '''Decorator that sends exceptions to an administrator via Slack DM
    and then swallows them.  The first argument of the function must be
    the config.'''
    import socket, urllib.error
    @wraps(f)
    def wrapper(config, *args, **kwargs):
        def send(message):
            try:
                client = WebClient(token=config.slack_token)
                channel = client.conversations_open(users=[config.error_notification])['channel']['id']
                client.chat_postMessage(channel=channel, text=message)
                # but always also print to the logs
                print(message)
            except Exception:
                traceback.print_exc()
        try:
            return f(config, *args, **kwargs)
        except Fail as e:
            # Nothing else caught this; just report the error string.
            send(str(e))
        except HandledError:
            pass
        except JIRAError as e:
            if e.status_code == 401:
                # Searches sometimes throw 401 errors.  Don't send message.
                print(e)
            else:
                send(f'Caught exception:\n```\n{traceback.format_exc()}```')
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
        self._jira = Jira(config)
        self._called = False

    def __call__(self):
        assert not self._called
        self._called = True

        message = self._event.text.replace(f'<@{self._config.slack_id}>', '').strip()
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
        self._reply(f"I didn't understand that.  Try `<@{self._config.slack_id}> help`")
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

    def _issue_link(self, issue, text=None, icon=False):
        '''Format an Issue into a Slack link.'''
        def link(format):
            start, icon_, stop = format[0].strip(), f':{format[1:-1]}: ' if icon else '', format[-1].strip()
            text_ = str(text) if text else issue.fields.summary
            return f'{start}<{issue.permalink()}|{icon_}{escape(text_)}>{stop}'
        status = issue.fields.status.name
        if status in ('New', 'ASSIGNED'):
            return link('*jira-1992*')
        if status == 'POST':
            if self._jira.BOOTIMAGE_ISSUE_BUILT_LABEL in issue.fields.labels:
                if self._jira.BOOTIMAGE_ISSUE_VERIFIED_LABEL in issue.fields.labels:
                    return link('_large_green_circle_')
                return link(' test_tube ')
            return link(' branch ')
        if status in ('MODIFIED', 'ON_QA', 'Verified', 'Closed'):
            return link('~checkyes~')
        return link('¿thinking_face?')

    @register(('backport',), ('issue-url-or-key', 'minimum-release'),
            doc='ensure there are backport issues down to minimum-release')
    def _backport(self, desc, min_ver):
        '''Ensure the existence of backport issues for the specified issue,
        in all releases >= the specified one.'''
        # Fail if release is invalid or current
        if min_ver not in self._config.releases:
            raise Fail(f'Unknown release "{escape(min_ver)}".')
        if min_ver == self._config.releases.current.label:
            raise Fail(f"{escape(min_ver)} is the current release; can't backport.")

        # Look up the issue.  This validates the project and component.
        issue = self._jira.issue(desc, [
            'affects_versions',
            'assignee',
            'issuetype',
            'security',
            'severity',
        ])
        if issue.fields.severity is None:
            # Eric-Paris-bot will unset the target version without a severity
            raise Fail("Issue severity is not set; can't backport.")
        # Find any issues we block that have Security and not SecurityTracking
        # label.  We'll need any new backport issues to block those issues as
        # well.
        blocks = self._jira.search_issues(
            'labels = "Security"',
            'labels != "SecurityTracking"',
            blocked_by=issue.id,
            default_component=False,
        )

        # Query existing backport issues
        backports = self._jira.get_backports(issue, min_ver=min_ver)

        # Query bootimage trackers if needed
        need_bootimage = self._jira.BOOTIMAGE_ISSUE_LABEL in issue.fields.labels
        if need_bootimage:
            self._jira.ensure_bootimage_issue_allowed(issue)
            trackers = self._jira.get_bootimage_trackers()

        # First, do checks
        created_trackers = []
        for rel in list(self._config.releases.at_least(min_ver).previous.values())[len(backports):]:
            if need_bootimage:
                if rel.label not in trackers:
                    trackers[rel.label], created = self._jira.create_bootimage_tracker(rel)
                    if created:
                        created_trackers.append(self._issue_link(trackers[rel.label], rel.label))

        # Walk each backport version
        cur_issue = issue
        later_rel = self._config.releases.current
        created_issues = []
        all_issues = []
        for rel in self._config.releases.at_least(min_ver).previous.values():
            if backports:
                # Have an existing issue
                cur_issue = backports.pop(0)
            else:
                # Make a new one
                fields = {
                    self._jira.field('issuetype'): issue.fields.issuetype.name,
                    self._jira.field('project'): issue.fields.project.key,
                    self._jira.field('components'): [{'name': c.name} for c in issue.fields.components],
                    self._jira.field('summary'): f'[{rel.label}] {issue.fields.summary}',
                    self._jira.field('description'): f'Backport the fix for {issue.key} to {rel.label}.',
                    self._jira.field('severity'): {'value': issue.fields.severity.value},
                    self._jira.field('labels'): issue.fields.labels,
                    self._jira.field('affects_versions'): [{'name': v.name} for v in issue.fields.affects_versions],
                    self._jira.field('target_versions'): [{'name': rel.target_version}],
                }
                if hasattr(issue.fields, 'security'):
                    fields[self._jira.field('security')] = {'name': issue.fields.security.name}
                if need_bootimage:
                    fields[self._jira.field('labels')].append(self._jira.BOOTIMAGE_ISSUE_LABEL)
                prev_issue = cur_issue
                cur_issue = self._jira.api.create_issue(fields=fields)
                self._jira.api.assign_issue(
                    cur_issue.id,
                    issue.fields.assignee.name if issue.fields.assignee else None
                )
                self._jira.api.transition_issue(cur_issue.id, 'ASSIGNED')
                self._jira.create_issue_links(cur_issue.key,
                        clones=[prev_issue.key], blocked_by=[prev_issue.key],
                        blocks=[b.key for b in blocks])
                if need_bootimage:
                    self._jira.create_issue_links(cur_issue.key,
                            blocked_by=[trackers[rel.label].key])
                created_issues.append(self._issue_link(cur_issue, rel.label))
                if need_bootimage:
                    # Ensure this bootimage tracker is blocked by the one for
                    # the more recent release.  Thus we dynamically track
                    # bootimage tracker dependencies rather than imposing a
                    # fixed relationship between bumps in adjacent releases.
                    # For example, a bump for 4.6 may coalesce the contents
                    # of two 4.7 bumps.
                    if trackers[rel.label].id not in trackers[later_rel.label].blocks:
                        self._jira.create_issue_links(
                            trackers[later_rel.label].key,
                            blocks=[trackers[rel.label].key]
                        )
            all_issues.append(self._issue_link(cur_issue, rel.label))
            later_rel = rel

        created_issues.reverse()
        all_issues.reverse()
        message = ''
        if created_trackers:
            message += f'Created bootimage trackers: {", ".join(created_trackers)}\n'
        if created_issues:
            message += f'Created issues: {", ".join(created_issues)}\n'
        message += f'All backports: {", ".join(all_issues)}'
        self._reply(message, at_user=False)

    @register(('bootimage', 'create'), ('release',),
            doc='create bootimage tracker (usually done automatically as needed)')
    def _bootimage_create(self, label):
        try:
            rel = self._config.releases[label]
        except KeyError:
            raise Fail(f'Unknown release "{escape(label)}".')
        issue, created = self._jira.create_bootimage_tracker(rel)
        link = self._issue_link(issue, rel.label)
        self._reply(f'{"Created" if created else "Existing"} bootimage tracker: {link}', at_user=False)

    @register(('bootimage', 'list'), doc='list upcoming bootimage bumps')
    def _bootimage_list(self):
        '''List bootimage tracker issues.'''
        sections = (
            ('Planned bootimage bumps', 'ASSIGNED'),
            ('Pending bootimage bumps', 'POST'),
        )
        report = []
        for caption, status in sections:
            trackers = self._jira.get_bootimage_trackers(status=status)
            if not trackers:
                continue
            report.append(f'\n*_{caption}_*:')
            for label, rel in self._config.releases.items():
                try:
                    tracker = trackers[label]
                except KeyError:
                    # nothing for this release
                    continue
                issues = self._jira.get_bootimage_issues(tracker, rel)
                report.append('\n*For* ' + self._issue_link(tracker, label) + ':')
                for issue in issues:
                    report.append(self._issue_link(issue, icon=True))
                if not issues:
                    report.append('_no issues_')
        if not report:
            report.append('No bootimage bumps.')
        self._reply('\n'.join(report), at_user=False)

    @register(('bootimage', 'bug', 'add'), ('issue-url-or-key',),
            doc='add an issue and its backports to planned bootimage bumps')
    def _bootimage_bug_add(self, desc):
        '''Add an issue and its backports to planned bootimage bumps.'''
        # Look up the issue.  This validates the project and component.
        issue = self._jira.issue(desc)
        self._jira.ensure_bootimage_issue_allowed(issue)

        # Get planned bootimage bumps
        trackers = self._jira.get_bootimage_trackers()

        # Get issue and its backports
        issues = [issue] + self._jira.get_backports(issue)

        # First, do checks
        created_trackers = []
        for rel, cur_issue in zip(self._config.releases.values(), issues):
            assert cur_issue.fields.target_versions[0].name in rel.target_versions
            if rel.label not in trackers:
                trackers[rel.label], created = self._jira.create_bootimage_tracker(rel)
                if created:
                    created_trackers.append(self._issue_link(trackers[rel.label], rel.label))
            if self._jira.BOOTIMAGE_ISSUE_LABEL not in cur_issue.fields.labels:
                if cur_issue.fields.status.name not in ('New', 'ASSIGNED', 'POST'):
                    raise Fail(f'Refusing to add {cur_issue.key} in {cur_issue.fields.status.name} to bootimage tracker.')

        # Add to bootimage trackers; generate report
        later_rel = None
        added_issues = []
        all_issues = []
        for rel, cur_issue in zip(self._config.releases.values(), issues):
            link = self._issue_link(cur_issue, rel.label)
            all_issues.append(link)
            if self._jira.BOOTIMAGE_ISSUE_LABEL not in cur_issue.fields.labels:
                self._jira.create_issue_links(
                    cur_issue.key,
                    blocked_by=[trackers[rel.label].key],
                )
                cur_issue.update(fields={
                    'labels': cur_issue.fields.labels + [self._jira.BOOTIMAGE_ISSUE_LABEL]
                })
                added_issues.append(link)
                if later_rel is not None:
                    # Ensure this bootimage tracker is blocked by the one for
                    # the more recent release.  Thus we dynamically track
                    # bootimage dependencies rather than imposing a fixed
                    # relationship between bumps in adjacent releases.  For
                    # example, a bump for 4.6 may coalesce the contents of
                    # two 4.7 bumps.
                    if trackers[rel.label].id not in trackers[later_rel.label].blocks:
                        self._jira.create_issue_links(
                            trackers[later_rel.label].key,
                            blocks=[trackers[rel.label].key],
                        )
            later_rel = rel

        # Show report
        added_issues.reverse()
        all_issues.reverse()
        message = ''
        if created_trackers:
            message += f'Created bootimage trackers: {", ".join(created_trackers)}\n'
        if added_issues:
            message += f'Added to bootimage tracker: {", ".join(added_issues)}\n'
        message += f'All issues: {", ".join(all_issues)}'
        self._reply(message, at_user=False)

    @register(('bootimage', 'bug', 'built'), ('issue-url-or-key',),
            doc='mark an issue landed in an RHCOS build and ready for QE')
    def _bootimage_bug_built(self, desc):
        # Look up the issue.  This validates the project and component.
        issue = self._jira.issue(desc)
        self._jira.ensure_bootimage_issue_allowed(issue)

        if self._jira.BOOTIMAGE_ISSUE_LABEL not in issue.fields.labels:
            raise Fail(f'{issue.key} is not attached to a bootimage tracker.')
        if issue.fields.status.name not in ('New', 'ASSIGNED', 'POST'):
            raise Fail(f'Refusing to mark {issue.key} built from status {issue.fields.status.name}.')
        if self._jira.BOOTIMAGE_ISSUE_BUILT_LABEL not in issue.fields.labels:
            if issue.fields.status.name != 'POST':
                self._jira.api.transition_issue(issue.id, 'POST')
            issue.update(fields={
                'labels': issue.fields.labels + [self._jira.BOOTIMAGE_ISSUE_BUILT_LABEL],
            })
            self._jira.api.add_comment(
                issue.id,
                "This issue has been reported fixed in a new RHCOS build and is ready for QE verification.  To mark the issue verified, add the {{verified}} label.  This issue will automatically move to MODIFIED once the fix has landed in a new bootimage.",
            )

    @register(('bootimage', 'bug', 'list'),
            doc='list bugs on upcoming bootimage bumps')
    def _bootimage_bug_list(self):
        sections = (
            ('Planned bootimage bumps', 'ASSIGNED'),
            ('Pending bootimage bumps', 'POST'),
        )
        report = []
        for caption, status in sections:
            trackers = self._jira.get_bootimage_trackers(status=status)
            progenitors = {} # progenitor issue ID -> Issue
            groups = {} # progenitor issue ID -> [issue links]
            canonical = {} # backport issue ID -> progenitor issue ID
            for label, rel in self._config.releases.items():
                try:
                    tracker = trackers[label]
                except KeyError:
                    # nothing for this release
                    continue
                issues = self._jira.get_bootimage_issues(tracker, rel)
                for issue in issues:
                    # Find the progenitor from this issue's parent.  Maybe
                    # there is none, and we're the progenitor.
                    progenitor = (
                        [canonical[i] for i in issue.clones if i in canonical] +
                        [issue.id]
                    )[0]
                    # Add the next link in the ancestry chain
                    canonical[issue.id] = progenitor
                    # If we're the progenitor, record issue details
                    progenitors.setdefault(progenitor, issue)
                    # Associate this issue's link with the progenitor
                    groups.setdefault(progenitor, []).append(
                        self._issue_link(issue, rel.label, icon=True)
                    )
            if progenitors:
                report.append(f'\n*_{caption}_*:')
                # Python 3.7+ guarantees to preserve dict insertion order
                for id, issue in progenitors.items():
                    report.append(f'• {escape(issue.fields.summary)} [{", ".join(groups[id])}]')
        if not report:
            report.append('No bootimage trackers.')
        self._reply('\n'.join(report), at_user=False)

    @register(('release', 'list'), doc='list known releases',
            fast=True, complete=False)
    def _release_list(self):
        report = []
        for rel in reversed(self._config.releases.values()):
            aliases = f'~{" ".join(rel.target_version_aliases)}~' if rel.target_version_aliases else ''
            report.append(f'{rel.label}: _{rel.affects_version}_ *{rel.target_version}* {aliases}')
        body = "\n".join(report)
        self._reply(f'Release: _affects-version_ *default-target-version* ~other-target-versions~\n{body}\n', at_user=False)

    @register(('ping',), doc='check whether the bot is running properly',
            fast=True)
    def _ping(self):
        # Check Jira connectivity
        try:
            self._jira.api.myself()
        except Exception:
            # Swallow exception details and just report the failure
            raise Fail('Cannot contact Jira.')

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
def periodic(config, db, jira, maintenance):
    '''Run periodic tasks.'''

    # Prune database
    if maintenance:
        with db:
            db.prune_events()

    # Find issues with status MODIFIED or later which are attached to
    # bootimage trackers in POST or earlier, and move the issues back to POST.
    for status in ('ASSIGNED', 'POST'):
        jira.update_bootimage_issue_status(
            status,
            ['MODIFIED', 'ON_QA', 'Verified', 'Closed'],
            'POST',
            'The fix for this issue will not be delivered to customers until it lands in an updated bootimage.  That process is tracked in {tracker}, which has status {status}.  Moving this issue back to POST.',
        )

    # Find POST+built issues which are attached to bootimage trackers in
    # MODIFIED or ON_QA, and move them to MODIFIED.
    for status in ('MODIFIED', 'ON_QA'):
        jira.update_bootimage_issue_status(
            status,
            ['POST'],
            'MODIFIED',
            'The fix for this issue has landed in a bootimage bump, as tracked in {tracker} (now in status {status}).  Moving this issue to MODIFIED.',
            built=True,
        )


def main():
    parser = argparse.ArgumentParser(
            description='Jira helper bot for Slack.')
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
        ('RHCOSBOT_JIRA_TOKEN', 'jira-token'),
        ('RHCOSBOT_SLACK_APP_TOKEN', 'slack-app-token'),
        ('RHCOSBOT_SLACK_TOKEN', 'slack-token'),
    )
    for env, config_key in env_map:
        v = os.environ.get(env)
        if v:
            setattr(config, config_key, v)

    # Connect to services
    client = WebClient(token=config.slack_token)
    # store our user ID
    config.slack_id = client.auth_test()['user_id']
    # need to look up custom fields before constructing a Jira object
    api = Jira.connect(config)
    try:
        api.myself()['name']
    except JIRAError:
        raise Exception('Did not authenticate')
    config.fields = {f['name']: f['id'] for f in api.fields()}
    jira = Jira(config)
    db = Database(config)

    # Start socket-mode listener in the background
    socket_client = SocketModeClient(app_token=config.slack_app_token,
            web_client=WebClient(token=config.slack_token))
    socket_client.socket_mode_request_listeners.append(
            lambda socket_client, req: process_event(config, socket_client, req))
    socket_client.connect()

    # Run periodic tasks
    maint_period = config.jira_maintenance_interval // config.jira_poll_interval
    for i in itertools.count():
        periodic(config, db, jira, i % maint_period == 0)
        time.sleep(config.jira_poll_interval)


if __name__ == '__main__':
    main()
