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

from typing import Any, Set, Dict, List, Union, Optional
from dataclasses import dataclass

import tabulate


@dataclass
class Violation:
    '''
    Description
    -----------
    This is a dataclass to represent a violation found by the ExpectedComparator.

    Fields
    ------
    rule : str
        The rule in which there was a violation.
    func_name : str
        The function in which there was a violation. Used for parametric rules, set to ''
        if the rule is non-parametric.
    actual_result : str
        The result that was received by the run.
    expected_result : str
        The result that was expected to be received.
    '''
    rule: str
    func_name: str
    actual_result: str
    expected_result: str

    def __hash__(self) -> int:
        '''
        Summary
        -------
        Hashes the dataclass based on it's rule and func_name so it can be used in sets.

        Returns
        -------
        int
            The hash.
        '''
        return hash((self.rule, self.func_name))


class ExpectedComparator:
    '''
    Description
    -----------
    The ExpectedComparator is an object used to compare between results of the prover to an expected results file.
    The expected results file is basically an output of the verification process from a previous run so we'll
    know what to expect.

    The rules results are represented as a dictionary that maps a rule name to it's results.
    The results can be either a simple string indicating the status or it can be another dictionary if the
    rule is parametric. This dictionary maps between a status to a list of the functions that received this status.

    Using this object is as simple as instantiating one and calling the get_violation_table to
    receive a table string representation of all the violations found.
    '''
    _RULE_UNDEFINED_TAG = '\033[33mundefined\033[0m'
    _TABLE_HEADERS = ['Rule', 'Function', 'Result', 'Expected']

    def __init__(self, actual_rules_results: Dict[str, Union[str, Dict[str, List[str]]]],
                 expected_rules_results: Dict[str, Union[str, Dict[str, List[str]]]],
                 actual_assert_messages: Dict[str, Any],
                 expected_assert_messages: Dict[str, Any]) -> None:
        '''
        Summary
        -------
        Initializes the ExpectedComparator with the actual and expected results dictionaries for the rules
        and assert messages, and automatically makes the comparison.

        Parameters
        ----------
        actual_rules_results : dict[str, str | dict[str, list[str]]]
            The actual rules results dictionary received by the prover.
        expected_rules_results : dict[str, str | dict[str, list[str]]]
            The expected rules results dictionary.
        actual_assert_messages : dict[str, any]
            The actual assert messages received by the prover.
        expected_assert_messages : dict[str, any]
            The expected assert messages.
        '''
        self._assert_errors: Set[str] = set()
        self._violations: Set[Violation] = set()

        self._has_violations = not self._compare_results_with_expected(actual_rules_results, expected_rules_results,
                                                                       actual_assert_messages, expected_assert_messages)

    @property
    def has_violations(self) -> bool:
        '''
        Summary
        -------
        Property for if the ExpectedComparator found any violations.

        Returns
        -------
        bool
            Indication of the property.
        '''
        return self._has_violations

    def get_violations_table(self) -> str:
        '''
        Summary
        -------
        Tabulates the violations found by the ExpectedComparator.

        Returns
        -------
        str
            The tabulated violations.
        '''
        return tabulate.tabulate([[v.rule, v.func_name, v.actual_result, v.expected_result] for v in self._violations],
                                 headers=ExpectedComparator._TABLE_HEADERS, tablefmt='psql')

    def _add_violation(self, rule: str, func_name: str, actual_result: str, expected_result: str) -> None:
        '''
        Summary
        -------
        Adds a violation to the violations set.

        Parameters
        ----------
        rule : str
            The rule in which there was a violation.
        func_name : str
            The function in which there was a violation. Used for parametric rules, set to ''
            if the rule is non-parametric.
        actual_result : str
            The result that was received by the run.
        expected_result : str
            The result that was expected to be received.
        '''
        self._violations.add(Violation(rule, func_name, actual_result, expected_result))

    def _compare_results_with_expected(self, actual_rules_results: Dict[str, Union[str, Dict[str, List[str]]]],
                                       expected_rules_results: Dict[str, Union[str, Dict[str, List[str]]]],
                                       actual_assert_messages: Dict[str, Any],
                                       expected_assert_messages: Dict[str, Any]) -> bool:
        '''
        Summary
        -------
        Compares the actual with the expected results. The comparison is comparing the actual and expected
        rules results to see that all rules in the actual got the same status that we expected. It will
        later compare to see that we actually received results for every rule that we expected. At the end
        it will compare the assert messages.

        Parameters
        ----------
        actual_rules_results : dict[str, str | dict[str, list[str]]]
            The actual rules results dictionary received by the prover.
        expected_rules_results : dict[str, str | dict[str, list[str]]]
            The expected rules results dictionary.
        actual_assert_messages : dict[str, any]
            The actual assert messages received by the prover.
        expected_assert_messages : dict[str, any]
            The expected assert messages.

        Returns
        -------
        bool
            True if the comparison found no violations within the rules and the assert messages are alike.
            False otherwise.
        '''
        if actual_rules_results != expected_rules_results:
            # Compare results in expected.
            self._compare_rules_results(actual_rules_results, expected_rules_results)
            # Check for rules that were expected but didn't get results.
            self._find_not_existing_rules(actual_rules_results, expected_rules_results)
        # If assertMessages field is defined (in tester).
        assert_msg_test = True
        if expected_assert_messages:
            assert_msg_test = self._compare_assert_messages(actual_assert_messages, expected_assert_messages)

        return assert_msg_test and len(self._violations) == 0

    def _compare_rules_results(self, actual_rules_results: Dict[str, Union[str, Dict[str, List[str]]]],
                               expected_rules_results: Dict[str, Union[str, Dict[str, List[str]]]]) -> None:
        '''
        Summary
        -------
        Compares the rules results. Based on different flags and version of the prover, the same rule can be
        sometime represented as a 'flat' rule and sometimes as a parametric (nested) rule. The comparison should take
        that into account.

        This gives us then 4 different cases:
        1. The rule is flat both in the actual result and the expected.
            In this case we just compare their string status.
        2. The rule is flat in the actual results but parametric in the expected.
            In this case we will flatten the status of the rule based on it's different functions statuses
            and compare.
        3. The rule is parametric in the actual but is flat in the expected result.
            We handle this case similar to 2.
        4. The rule is parametric both in the actual result and the expected.
            In this case we'll check that every function of the actual result has the same status in the
            expected.

        Parameters
        ----------
        actual_rules_results : dict[str, str | dict[str, list[str]]]
            The actual rules results dictionary received by the prover.
        expected_rules_results : dict[str, str | dict[str, list[str]]]
            The expected rules results dictionary.
        '''

        for rule, rule_result in actual_rules_results.items():
            if rule in expected_rules_results:
                expected_rule_result = expected_rules_results[rule]
                if isinstance(rule_result, str):  # If the rule is flat in the results.
                    if isinstance(expected_rule_result, str):  # And the rule is flat in the expected as well.
                        if rule_result != expected_rule_result:
                            self._add_violation(rule, '', rule_result, expected_rule_result)
                    else:  # But the rule is nested in the expected.
                        nested_rule_res = ExpectedComparator._extract_nested_rules_status(expected_rule_result)
                        if rule_result != nested_rule_res:
                            self._add_violation(rule, '', rule_result, nested_rule_res)
                else:  # If the rule is nested in the results.
                    if isinstance(expected_rule_result, str):  # But the rule is not nested in the expected.
                        nested_rule_res = ExpectedComparator._extract_nested_rules_status(rule_result)
                        if nested_rule_res != expected_rule_result:
                            self._add_violation(rule, '', nested_rule_res, expected_rule_result)
                    else:  # Both rules are nested.
                        if rule_result != expected_rule_result:
                            self._compare_nested_rules(rule, rule_result, expected_rule_result)
            else:
                rule_result = (rule_result if isinstance(rule_result, str)
                               else ExpectedComparator._extract_nested_rules_status(rule_result))
                self._add_violation(rule, '', rule_result, ExpectedComparator._RULE_UNDEFINED_TAG)

    def _compare_nested_rules(self, rule: str, actual_result: Dict[str, List[str]],
                              expected_result: Dict[str, List[str]]) -> None:
        '''
        Summary
        -------
        Recursively compares a rule that came out as parametric (nested) in both the actual and expected results.
        In order to do this comparison we are "flipping" the results dictionaries, mapping each function to
        its status and then checking that each function in the actual results has the same status in the expected.
        If a function in the actual wasn't found in the expected it will be marked with an "undefined tag"
        and vice-versa.

        Parameters
        ----------
        rule : str
            The rule we are comparing, in case we'll have a violation to fill.
        actual_result : dict[str, Union[str, List[str]]]
            The actual nested result for the rule received by the prover.
        expected_result : dict[str, Union[str, List[str]]]
            The expected nested result for the rule.
        '''
        def flatten_nested_dict(nested_dict: Dict, flat_dict: Any = None, parent_key: str = '') -> Dict:
            if flat_dict is None:
                flat_dict = {}
            for key, value in nested_dict.items():
                new_key = f"{parent_key}.{key}" if parent_key else key
                if isinstance(value, dict):
                    flatten_nested_dict(value, flat_dict, new_key)
                elif isinstance(value, list):
                    for item in value:
                        flat_dict[item] = key
                else:
                    flat_dict[new_key] = value
            return flat_dict

        actual_result_flat = flatten_nested_dict(actual_result)
        expected_result_flat = flatten_nested_dict(expected_result)

        for func, func_result in actual_result_flat.items():
            expected_func_result = expected_result_flat.get(func, ExpectedComparator._RULE_UNDEFINED_TAG)
            if func_result != expected_func_result:
                self._add_violation(rule, func, func_result, expected_func_result)

        # Find functions in the expected results that aren't in the actual ones
        for func, func_result in expected_result_flat.items():
            if func not in actual_result_flat:
                self._add_violation(rule, func, ExpectedComparator._RULE_UNDEFINED_TAG, func_result)

    def _find_not_existing_rules(self, actual_rules_results: Dict[str, Union[str, Dict[str, List[str]]]],
                                 expected_rules_results: Dict[str, Union[str, Dict[str, List[str]]]]) -> None:
        '''
        Summary
        -------
        Checks for rules that are expected to get a result but didn't and mark them with an
        "undefined tag".

        Parameters
        ----------
        actual_rules_results : dict[str, str | dict[str, list[str]]]
            The actual rules results dictionary received by the prover.
        expected_rules_results : dict[str, str | dict[str, list[str]]]
            The expected rules results dictionary.
        '''
        # Casting a dictionary to a set is using only the keys.
        rules_not_found = set(expected_rules_results) - set(actual_rules_results)
        for r in rules_not_found:
            expected_result = expected_rules_results[r]
            expected_result = (expected_result if isinstance(expected_result, str)
                               else ExpectedComparator._extract_nested_rules_status(expected_result))
            self._add_violation(r, '', ExpectedComparator._RULE_UNDEFINED_TAG, expected_result)

    def _compare_assert_messages(self,
                                 actual_assert_messages: Dict[str, Any],
                                 expected_assert_messages: Dict[str, Any]) -> bool:
        '''
        Summary
        -------
        Compares the assert messages received by the proved to the expected.

        Parameters
        ----------
        actual_assert_messages : dict[str, any]
            The actual assert messages received by the prover.
        expected_assert_messages : dict[str, any]
            The expected assert messages.

        Returns
        -------
        bool
            Whether the comparison succeeded.
        '''
        test = True
        for rule in expected_assert_messages.keys():
            # Current rule is missing from 'assertMessages' section in current results.
            if rule not in actual_assert_messages:
                test = False
                self._assert_errors.add(f'Rule "{rule}" does not appear in the output.' +
                                        'Please remove unnecessary rules.')
            # Assertion messages are different from each other
            elif expected_assert_messages[rule] != actual_assert_messages[rule]:
                test = False
                self._assert_errors.add(f'Rule "{rule}": wrong assertion message. ' +
                                        f'Got: "{actual_assert_messages[rule]}".' +
                                        f'Expected: "{expected_assert_messages[rule]}".')
        return test

    @staticmethod
    def _extract_nested_rules_status(nested_rule: Dict[str, List[str]], collected_statuses: Optional[Set[str]] = None) \
            -> str:
        """
        Summary
        -------
        A utility function to flatten and extract the status of a parametric (nested) rule using the following logic:
        A parametric rule is successful if and only if all of its functions succeed.
        Otherwise, we flatten based on the status of at least one function in the following order:
        UNKNOWN > TIMEOUT > FAIL > SANITY_FAIL.
        For example, if at least one function receives UNKNOWN, the whole rule status is considered UNKNOWN,
        even if there are functions that received TIMEOUT or FAIL.

        Parameters
        ----------
        nested_rule : dict[str, Union[str, dict[str, list[str]]]]
            The nested rule to flatten.

        collected_statuses : set[str]
            A set to store unique statuses encountered during flattening.

        Returns
        -------
        str
            The flattened status.
        """
        collected_statuses = set() if collected_statuses is None else collected_statuses

        result = ExpectedComparator.__check_parametric_rule(nested_rule)
        if result:
            collected_statuses.add(result)

        for _, value in nested_rule.items():
            if isinstance(value, str):
                if value != 'SUCCESS':
                    collected_statuses.add(value)
            elif isinstance(value, dict):
                ExpectedComparator._extract_nested_rules_status(value, collected_statuses)

        statuses = ['UNKNOWN', 'TIMEOUT', 'FAIL', 'SANITY_FAIL']
        return next((s for s in statuses if s in collected_statuses), 'SUCCESS')

    @staticmethod
    def __check_parametric_rule(rule: dict) -> str:
        """
        Check status for parametric rule.

        Parameters
        ----------
        rule : dict
            The parametric rule to check.

        Returns
        -------
        str
            The first encountered status in the order: 'UNKNOWN', 'TIMEOUT', 'FAIL', 'SANITY_FAIL'.
        """
        statuses = ['UNKNOWN', 'TIMEOUT', 'FAIL', 'SANITY_FAIL']
        return next((s for s in statuses if rule.get(s)), '')
