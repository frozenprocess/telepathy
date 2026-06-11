#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 The Telepathy Authors
#
# This file is part of Telepathy.
#
# Telepathy is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License version 3 as published
# by the Free Software Foundation.
#
# Telepathy is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
# more details.
#
# telepathy-ci.sh — the body of the Telepathy GitHub Action (action.yml).
#
# It drives the calico-engine Docker image to do two things in a CI run:
#
#   test  — gate the topology against an assertions file (fails the job on a
#           failed assertion).
#   diff  — evaluate the policy on the PR's base ref and on the head, and report
#           the flows that changed (opened/closed/added/removed) as a sticky PR
#           comment + a job-summary table.
#
# Everything runs through the image (no host Go toolchain), so a consumer only
# needs Docker — which every GitHub-hosted runner already has. Inputs arrive as
# INPUT_* env vars (action.yml maps each `inputs.x` to INPUT_X).
set -euo pipefail

IMAGE="${INPUT_IMAGE:?image input required}"
TOPOLOGY="${INPUT_TOPOLOGY:?topology input required}"
POLICY="${INPUT_POLICY:?policy input required}"
ASSERTIONS="${INPUT_ASSERTIONS:-}"
MODE="${INPUT_MODE:-auto}"
BASE_REF="${INPUT_BASE_REF:-}"
DO_COMMENT="${INPUT_COMMENT:-true}"
FAIL_ON_DIFF="${INPUT_FAIL_ON_DIFF:-false}"
TOKEN="${INPUT_GITHUB_TOKEN:-${GITHUB_TOKEN:-}}"

WS="${GITHUB_WORKSPACE:-$PWD}"
OUT="$WS/.telepathy"
SUMMARY="${GITHUB_STEP_SUMMARY:-/dev/stdout}"
mkdir -p "$OUT"

# run_engine invokes the engine image over the mounted workspace. The image
# entrypoint IS the binary, so the arguments here are calico-engine arguments.
# Output is captured by the caller's redirect (host-side), so produced files are
# owned by the runner, not root.
run_engine() {
	docker run --rm -i -v "$WS":/w -w /w "$IMAGE" "$@"
}

fail=0

# resolve "auto": run both gates when an assertions file is supplied, otherwise
# just the diff.
if [ "$MODE" = "auto" ]; then
	if [ -n "$ASSERTIONS" ]; then MODE="both"; else MODE="diff"; fi
fi

run_test() {
	echo "::group::telepathy test ($ASSERTIONS)"
	if run_engine test -assert "$ASSERTIONS" -policy "$POLICY" <"$TOPOLOGY" | tee "$OUT/test.txt"; then
		echo "✅ all connectivity assertions passed"
	else
		fail=1
		echo "::error title=Telepathy::connectivity assertions failed (see log)"
	fi
	{
		echo "### 🔮 Telepathy — assertions"
		echo '```'
		cat "$OUT/test.txt"
		echo '```'
	} >>"$SUMMARY"
	echo "::endgroup::"
}

run_diff() {
	if [ -z "$BASE_REF" ]; then
		echo "::warning title=Telepathy::no base-ref to diff against (not a PR?), skipping connectivity diff"
		return
	fi
	echo "::group::telepathy diff ($BASE_REF -> HEAD)"

	# Materialise the base ref in a worktree under the workspace so a single
	# bind-mount covers both revisions. fetch-depth:0 on checkout makes this work
	# on a shallow clone.
	git fetch --no-tags origin "$BASE_REF"
	local base_tree="$WS/.telepathy-base"
	rm -rf "$base_tree"
	git worktree add --detach "$base_tree" FETCH_HEAD

	run_engine -policy "$POLICY" <"$TOPOLOGY" >"$OUT/head.json"
	run_engine -policy ".telepathy-base/$POLICY" <".telepathy-base/$TOPOLOGY" >"$OUT/base.json"
	run_engine diff -format markdown ".telepathy/base.json" ".telepathy/head.json" >"$OUT/diff.md"
	run_engine diff -format json ".telepathy/base.json" ".telepathy/head.json" >"$OUT/diff.json"

	git worktree remove --force "$base_tree" 2>/dev/null || rm -rf "$base_tree"

	cat "$OUT/diff.md" >>"$SUMMARY"

	local changed opened closed
	changed=$(jq -r 'if (.changes | length) > 0 then "true" else "false" end' "$OUT/diff.json")
	opened=$(jq -r '.opened' "$OUT/diff.json")
	closed=$(jq -r '.closed' "$OUT/diff.json")
	{
		echo "changed=$changed"
		echo "opened=$opened"
		echo "closed=$closed"
	} >>"${GITHUB_OUTPUT:-/dev/null}"
	echo "diff: changed=$changed opened=$opened closed=$closed"

	if [ "$DO_COMMENT" = "true" ]; then post_comment; fi
	if [ "$FAIL_ON_DIFF" = "true" ] && [ "$changed" = "true" ]; then
		fail=1
		echo "::error title=Telepathy::connectivity changed and fail-on-diff is set"
	fi
	echo "::endgroup::"
}

# post_comment upserts a single sticky PR comment (found by a hidden marker) so
# repeated pushes update one comment instead of spamming the thread.
post_comment() {
	local pr
	pr=$(jq -r '.pull_request.number // empty' "${GITHUB_EVENT_PATH:-/dev/null}" 2>/dev/null || true)
	if [ -z "$pr" ]; then
		echo "not a pull_request event; comment written to job summary only"
		return
	fi
	if [ -z "$TOKEN" ]; then
		echo "::warning title=Telepathy::no github-token; skipping PR comment (summary still posted)"
		return
	fi

	local marker="<!-- telepathy-policy-impact -->"
	local body; body="$marker"$'\n'"$(cat "$OUT/diff.md")"
	export GH_TOKEN="$TOKEN"
	local repo="$GITHUB_REPOSITORY"

	local existing
	existing=$(gh api "repos/$repo/issues/$pr/comments" --paginate \
		--jq ".[] | select(.body | startswith(\"$marker\")) | .id" 2>/dev/null | head -n1 || true)
	if [ -n "$existing" ]; then
		gh api -X PATCH "repos/$repo/issues/comments/$existing" -f body="$body" >/dev/null
		echo "updated PR comment $existing"
	else
		gh api -X POST "repos/$repo/issues/$pr/comments" -f body="$body" >/dev/null
		echo "posted new PR comment"
	fi
}

case "$MODE" in
	test) [ -n "$ASSERTIONS" ] || { echo "::error::mode=test needs an assertions input"; exit 1; }; run_test ;;
	diff) run_diff ;;
	both)
		[ -n "$ASSERTIONS" ] && run_test
		run_diff
		;;
	*) echo "::error::unknown mode '$MODE' (want test|diff|both|auto)"; exit 1 ;;
esac

exit "$fail"
