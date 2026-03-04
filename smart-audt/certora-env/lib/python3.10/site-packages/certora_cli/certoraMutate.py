#!/usr/bin/env python3
#     The Certora Prover
#     Copyright (C) 2025  Certora Ltd.
#
#     This program is free software: you can redistribute it and/or modify
#     it under the terms of the GNU General Public License as published by
#     the Free Software Foundation, version 3 of the License.
#
#     This program is distributed in the hope that it will be useful,
#     but WITHOUT ANY WARRANTY; without even the implied warranty of
#     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#     GNU General Public License for more details.
#
#     You should have received a copy of the GNU General Public License
#     along with this program.  If not, see <https://www.gnu.org/licenses/>.


import sys

from pathlib import Path
from typing import List
from rich.console import Console


scripts_dir_path = Path(__file__).parent.resolve()  # containing directory
sys.path.insert(0, str(scripts_dir_path))

from Shared import certoraUtils as Util

from Mutate import mutateApp as App
from Mutate import mutateValidate as Mv


def mutate_entry_point() -> None:
    try:
        run_mutate_from_args(sys.argv[1:])
        sys.exit(0)
    except KeyboardInterrupt:
        Console().print("[bold red]\nInterrupted by user")
        sys.exit(1)
    except Util.CertoraUserInputError as e:
        if e.orig:
            print(f"\n{str(e.orig).strip()}")
        if e.more_info:
            print(f"\n{e.more_info.strip()}")
        Console().print(f"[bold red]\n{e}\n")
        sys.exit(1)
    except Exception as e:
        Console().print(f"[bold red]{e}")
        sys.exit(1)


def run_mutate_from_args(arg_list: List[str]) -> None:
    mutate_app = App.MutateApp(arg_list)
    run_mutate(mutate_app)


def run_mutate(mutate_app: App.MutateApp) -> None:

    mutate_app.read_conf_file()
    mutate_app.checks_before_settings_defaults()
    mutate_app.set_defaults()

    if mutate_app.collect_mode:
        run_mutate_collect(mutate_app)
    else:
        run_mutate_generate(mutate_app)


class IncompleteCollectFile(Exception):
    pass


def run_mutate_collect(mutate_app: App.MutateApp) -> None:
    """
    :param mutate_app:
    :return: None
    """
    if not mutate_app.collect_file:
        raise Util.ImplementationError("collect_file was not set in CLI or default")
    if mutate_app.test == str(Util.TestValue.CHECK_ARGS):
        raise Util.TestResultsReady(mutate_app)
    if not mutate_app.collect():
        raise IncompleteCollectFile()


def run_mutate_generate(mutate_app: App.MutateApp) -> None:

    if mutate_app.is_soroban_run():
        mutate_app.submit_soroban()
    else:
        if mutate_app.orig_run:
            mutate_app.read_conf_from_orig_run()

        mutate_app.settings_post_parsing()
        Util.check_packages_arguments(mutate_app.prover_context)

        validator = Mv.MutateValidator(mutate_app)
        validator.validate()

        if mutate_app.test == str(Util.TestValue.CHECK_ARGS):
            raise Util.TestResultsReady(mutate_app)

        App.check_key_exists()
        mutate_app.verify_orig_build()  # try to build orig from conf
        mutate_app.submit_evm()

        # default mode is async. That is, we both _submit_ and _collect_
        if mutate_app.sync:
            mutate_app.poll_collect()

if __name__ == '__main__':
    mutate_entry_point()
