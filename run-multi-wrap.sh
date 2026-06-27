#!/bin/bash
# Wrapper that runs all multi-binary test programs
# SPDX-License-Identifier: GPL-3.0-or-later

set -e
cd "$(dirname "$0")"
./tmulti1
./tmulti2
./tmulti3
./tnonunique
