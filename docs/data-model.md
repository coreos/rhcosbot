# Jira data model

## Release

- Is defined in the bot config file
- Has a `label` which is used to refer to the release in commands
- Has a `jira-affects-version` which is used when setting/matching the Jira _Affects Version/s_ field (`x.y`)
- Has a `jira-target-version` which is used when setting/matching the Jira _Target Version_ field (`x.y.0` or `x.y.z`)
- May have `jira-target-version-aliases` which are also used when matching the Jira _Target Version_ field (typically `x.y.0` after x.y.0 has been released and the target version has changed to `x.y.z`)

## Backported issue

- Is initialized to `ASSIGNED` status with the same _Assignee_, _Affects Version/s_, _Security Level_, and _Labels_ as the issue it backports
- Has the same _Type_ as the issue it backports
- Is in the bot's configured _Project_ and _Component_, and backports an issue in the same _Project_ and _Component_
- Has _Severity_ set, and backports an issue that has _Severity_ set
- Has a _Target Version_ corresponding to the next older release than the issue it backports
- _Clones_ and _is blocked by_ the corresponding bug with the next newer _Target Version_, in a backport chain up to the configured latest release
- _Blocks_ any issues blocked by the next newer release in the backport chain that have the `Security` label and don't have the `SecurityTracking` label
- Must be the only issue that _is cloned by_ the issue it backports with the same _Target Version_
- Is also a bootimage issue if any other issue in the backport chain is a bootimage issue
- Can have additional links to other issues

## Bootimage issue

- Has these states:
  - If it's being worked on, is in `New`, `ASSIGNED`, or `POST` status without special labels
  - If the fix has merged and landed in an RHCOS build, is in `POST` status with the `rhcos-image-built` label.  When adding this label, the bot posts a comment asking for QE verification.
  - If the fix has landed and been tested in an RHCOS build, is in `POST` status with the `rhcos-image-built` and `verified` labels
  - Once the bootimage tracker issue moves to `MODIFIED`, is moved to `MODIFIED` status by the bot if the issue has the `rhcos-image-built` label.  The bot posts a comment when doing so.
  - Cannot be moved to `MODIFIED` or later until the bootimage tracker issue is in `MODIFIED` or later.  The bot enforces this by moving the issue back to `POST` and posting a comment complaining about it.
- Does not need to be in the bot's configured _Project_ and _Component_, but must be manually added to the bootimage tracker issue in that case.  Bot timers will modify bootimage issues from outside the component, but bot commands will refuse to do so.
- Has the `rhcos-bootimage-needed` label
- Cannot have the `SecurityTracking` label
- Has an _Affects Version/s_ and a _Target Version_
- _Is blocked by_ the bootimage tracker issue that tracks it
- Also has the properties of a backported issue, if it is backported
- Can have additional links to other issues

## Bootimage tracker issue

- Is initialized to `ASSIGNED` status with _Assignee_ set to the bot
- Has _Type_ `Bug`
- Is in the bot's configured _Project_ and _Component_
- Has _Severity_ set
- Has a single _Affects Version/s_ and a corresponding _Target Version_
- Has the `rhcos-bootimage-tracker` label
- _Blocks_ bootimage issues
- _Blocks_ trackers for the next older release, and _is blocked by_ trackers for the next newer release, that include issues in the same backport chains as issues blocked by this tracker.  These relationships are created dynamically as bootimage issues are added to the tracker, and thus a tracker may be blocked by multiple trackers for the next newer release.
- _Clones_ the previous tracker for the same release, if any
- Cannot be in `NEW` status.  Can be in `ASSIGNED` if in progress (at most one tracker per release), `POST` once a PR is posted (at most one tracker per release), or `MODIFIED` or later.
- Can have additional links to other issues
