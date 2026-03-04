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

import os
import re
from pathlib import Path
from typing import List, Tuple, Dict, Set

from sly import Lexer  # type: ignore[import]
from sly import Parser  # type: ignore[import]
from sly.lex import Token  # type: ignore[import]
from sly.yacc import YaccProduction  # type: ignore[import]

from Shared import certoraUtils as Util


class SpecImportLexer(Lexer):
    """
        A lexer that creates designated tokens for 'import' keywords and strings literals in the given spec file.
    """

    def __init__(self, spec_file: Path, spec_content: str):
        self.spec_file = spec_file
        self.spec_content = spec_content

    tokens = {ANY, IMPORT, STRING}  # type: ignore # noqa: F821

    ignore = ' \t'  # Ignore whitespace and tab characters

    # Ignore comments; in particular, ignore commented out imports;
    ignore_comments_a = r'[/][/][^\n\r]*'

    @_(r'[/][*][\s\S]*?[*][/]')  # type: ignore # noqa: F821
    def ignore_comments_b(self, t: Token) -> None:
        self.lineno += t.value.count("\n")

    IMPORT = r'\bimport\b'  # First, match against 'import' keywords and string literals

    @_(r'\"[^"]*\"')  # type: ignore # noqa: F821
    def STRING(self, t: Token) -> Token:  # Extract the characters of the string literal, e.g., '"abc"' --> 'abc'
        result = re.search(r'[^"]+', t.value)
        if result:
            t.value = result.group(0)
        else:  # An empty string literal (i.e., '""')
            t.value = ''
        return t

    ANY = r'.'  # Default: Characters that have nothing to do with import declarations

    @_(r'\n+')  # type: ignore # noqa: F821
    def ignore_newline(self, t: Token) -> None:  # Ignore new line characters; use those to compute the line number
        self.lineno += len(t.value)

    # Error handling
    def error(self, t: Token) -> None:
        raise Util.CertoraUserInputError(f'{self.spec_file}:{self.lineno}:{self.find_column(t.index)}: '
                                         f'Encountered the illegal symbol {repr(t.value[0])}')

    # Computes the column number from the given token's index
    def find_column(self, token_index: int) -> int:
        last_cr = self.spec_content.rfind('\n', 0, token_index)
        if last_cr < 0:
            last_cr = 0
        column = (token_index - last_cr) + 1
        return column


class SpecImportParser(Parser):
    """
           A parser for import declarations of specification files, namely strings that have the form
           'IMPORT STRING'.
           NOTE: The parser should guarantee that if the spec file has a valid syntax, then all of its imports
           are parsed. In particular, no actual imports are omitted, and no
           non-existing or commented out imports are erroneously added.
           If the spec has an invalid syntax, we may over-approximate the actual set of imports,
           but we expect that the CVL parser would fail later.

    """

    def __init__(self, _lexer: SpecImportLexer):
        self.lexer = _lexer
        self.parse_error_msgs: List[str] = []

    # Get the token list from the lexer (required)
    tokens = SpecImportLexer.tokens

    # Grammar rules and actions
    @_('imports maybe_import_decl')  # type: ignore # noqa: F821,F811
    def imports(self, p: YaccProduction) -> List[Tuple[str, str]]:
        return p.imports if not p.maybe_import_decl else p.imports + p.maybe_import_decl

    @_('')  # type: ignore # noqa: F821,F811
    def imports(self, p: YaccProduction) -> List[Tuple[str, str]]:  # noqa: F821,F811
        return []

    @_('ANY', 'STRING')  # type: ignore # noqa: F821,F811
    def maybe_import_decl(self, p: YaccProduction) -> None:  # Surely NOT an import declaration
        return None

    @_('IMPORT STRING')  # type: ignore # noqa: F821,F811
    def maybe_import_decl(self, p: YaccProduction) -> List[Tuple[str, str]]:  # noqa: F821,F811
        # Surely an import declaration
        # Also log the location of the import declaration
        return [(p.STRING, f'{p.lineno}:{self.lexer.find_column(p.index)}')]

    def error(self, p: Token) -> Token:
        self.parse_error_msgs.append(fr'{self.lexer.spec_file}:{p.lineno}:{self.lexer.find_column(p.index)}: '
                                     fr'Did not expect the symbol {repr(p.value)}')  # log the error
        # Read ahead looking for an 'import' keyword.
        # If such a keyword is found, restart the parser in its initial state
        while True:
            p = next(self.tokens.__iter__(), None)
            if not p or p.type == 'IMPORT':
                break
            self.restart()
        return p  # Return IMPORT as the next lookahead token


class SpecWithImports:
    """
        .spec file together with the import declarations of .spec files that were collected transitively from it.
    """

    def __init__(self, _spec_file: str, _spec_idx: int, _abspath_imports_to_locs: Dict[str, Set[str]],
                 _spec_files_to_orig_imports: Dict[str, Set[str]]):

        self.spec_file = _spec_file  # The path of the main .spec file

        self.spec_idx = _spec_idx  # The index that will be prepended to the names of the main and imported .spec files

        #  The path where the main .spec file will eventually be copied to
        self.eventual_path_to_spec = self.__get_eventual_path_to_spec(Path(self.spec_file))

        # Maps absolute .spec import paths to locations of corresponding import declarations in the .spec files
        self.abspath_imports_to_locs = _abspath_imports_to_locs

        # Maps each .spec file to the import paths that appear in the import declarations that this file contains.
        # Each key is the absolute path of the .spec file
        self.spec_files_to_orig_imports = _spec_files_to_orig_imports

        # Maps each "eventual" path of a .spec file to the import paths that appear in this file.
        # The "eventual" path is where the .spec file will eventually be copied to;
        # e.g., "./someFolder/s.spec" -> .certora_config/{self.spec_idx}_s.spec
        self.eventual_path_to_orig_imports = {self.__get_eventual_path_to_spec(Path(abspath)): list(orig_imports) for
                                              abspath, orig_imports in self.spec_files_to_orig_imports.items()}

        #  Maps each absolute .spec import path to the one where the imported .spec file will eventually be copied to
        self.abspath_to_eventual_import_paths = {abspath: self.__get_eventual_path_to_spec(Path(abspath)) for abspath in
                                                 self.abspath_imports_to_locs.keys()}

        # Maps each "eventual" .spec import path to a (canonicalized) relative form of the original import declaration
        self.eventual_import_paths_to_relpaths = {
            self.__get_eventual_path_to_spec(Path(abspath)): str(Path(abspath).relative_to(Path().resolve()))
            for abspath in self.abspath_imports_to_locs.keys()
        }

        self.__assert_distinct_filenames()

    def __get_eventual_path_to_spec(self, path: Path) -> str:
        return f"{Util.get_certora_sources_dir()}/.{self.spec_idx}_{path.name}.spec"

    #  Checks that we don't have distinct import paths that share the same file names, e.g.,
    #  './folder/a.spec' and './otherFolder/a.spec'
    #  Also checks that there is no import path whose file name is the same as that of the main .spec file.
    #  Note: This is required because we copy all of the imported .spec files, together with the main .spec file,
    #  into the same directory.
    def __assert_distinct_filenames(self) -> None:

        def invalid_imports_str(invalid_imports: List[str]) -> str:
            return '\n'.join(
                [f'\"{abspath}\" @ {"; ".join(self.abspath_imports_to_locs[abspath])}' for abspath in
                 invalid_imports])

        distinct_imports_filenames = list(
            map((lambda path: os.path.basename(path)), self.abspath_imports_to_locs.keys()))

        distinct_imports_with_shared_filenames = \
            [path for path in self.abspath_imports_to_locs.keys() if
             distinct_imports_filenames.count(os.path.basename(path)) > 1]

        if distinct_imports_with_shared_filenames:
            raise Util.CertoraUserInputError(
                f'Expected all distinct .spec file imports to also have distinct file names, but got:\n'
                f'{invalid_imports_str(distinct_imports_with_shared_filenames)}')

        spec_file_basename = os.path.basename(self.spec_file)
        imports_with_spec_file_basename = [path for path in self.abspath_imports_to_locs.keys() if
                                           os.path.basename(path) == spec_file_basename]
        if imports_with_spec_file_basename:
            raise Util.CertoraUserInputError(
                f'Expected all .spec file imports to have file names different from \'{spec_file_basename}\', but got:'
                f'\n{invalid_imports_str(imports_with_spec_file_basename)}')
