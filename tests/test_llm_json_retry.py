"""Um modelo de raciocínio pode gastar o orçamento pensando e não dizer nada.

O Groq então responde `400 json_validate_failed` com `failed_generation` vazio — não há o
que recuperar do erro, e foi exatamente isso que travou o GovTokenEscrow em 09/11 e de novo
em 17/11. O que falta é espaço para a resposta, não outro prompt.
"""

import sys
import unittest
from pathlib import Path
from unittest import mock

from pydantic import BaseModel

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "agent"))

from llm import client as llm_client  # noqa: E402


class Falha(BaseModel):
    id: str


class Diagnostico(BaseModel):
    falhas: list[Falha]


EMPTY_GENERATION_ERROR = (
    "Error code: 400 - {'error': {'message': \"Failed to validate JSON. Please adjust your "
    "prompt. See 'failed_generation' for more details.\", 'type': 'invalid_request_error', "
    "'code': 'json_validate_failed', 'failed_generation': ''}}"
)


def _response(payload: str):
    return mock.Mock(choices=[mock.Mock(message=mock.Mock(content=payload))])


class RetryTests(unittest.TestCase):
    def _call(self, side_effect, model="openai/gpt-oss-120b", max_tokens=1400):
        create = mock.Mock(side_effect=side_effect)
        fake = mock.Mock()
        fake.chat.completions.create = create
        with mock.patch.object(llm_client, "get_client", return_value=fake):
            with mock.patch.object(llm_client, "MODELO_LLM", model):
                result = llm_client.chamar_ia_json(
                    "system", "user", Diagnostico, max_tokens=max_tokens
                )
        return result, create

    def test_an_empty_generation_is_retried_with_more_room(self):
        good = _response('{"falhas": [{"id": "VULN_001"}]}')
        result, create = self._call([Exception(EMPTY_GENERATION_ERROR), good])
        self.assertEqual(result, {"falhas": [{"id": "VULN_001"}]})
        self.assertEqual(create.call_count, 2)
        first, second = create.call_args_list
        self.assertEqual(first.kwargs["max_tokens"], 1400)
        self.assertEqual(second.kwargs["max_tokens"], 5600)
        self.assertEqual(second.kwargs["extra_body"], {"reasoning_effort": "low"})

    def test_the_retry_happens_only_once(self):
        with self.assertRaises(Exception):
            self._call([Exception(EMPTY_GENERATION_ERROR), Exception(EMPTY_GENERATION_ERROR)])

    def test_a_model_without_reasoning_gets_no_reasoning_parameter(self):
        good = _response('{"falhas": []}')
        _, create = self._call(
            [Exception(EMPTY_GENERATION_ERROR), good], model="llama-3.3-70b-versatile"
        )
        self.assertNotIn("extra_body", create.call_args_list[1].kwargs)

    def test_a_recoverable_failed_generation_is_still_recovered_without_a_second_call(self):
        error = (
            "Error code: 400 - {'error': {'code': 'json_validate_failed', "
            "'failed_generation': '{\"falhas\": [{\"id\": \"VULN_009\"}]}'}}"
        )
        result, create = self._call([Exception(error)])
        self.assertEqual(result, {"falhas": [{"id": "VULN_009"}]})
        self.assertEqual(create.call_count, 1)

    def test_an_unrelated_error_is_not_retried(self):
        # Um 429 por TPM é repetido (ver RateLimitRetryTests); um erro de servidor não.
        create = mock.Mock(side_effect=Exception("Error code: 500 - internal server error"))
        fake = mock.Mock()
        fake.chat.completions.create = create
        with mock.patch.object(llm_client, "get_client", return_value=fake):
            with self.assertRaises(Exception):
                llm_client.chamar_ia_json("system", "user", Diagnostico, max_tokens=1400)
        self.assertEqual(create.call_count, 1)

    def test_without_an_explicit_budget_the_retry_still_asks_for_room(self):
        good = _response('{"falhas": []}')
        create = mock.Mock(side_effect=[Exception(EMPTY_GENERATION_ERROR), good])
        fake = mock.Mock()
        fake.chat.completions.create = create
        with mock.patch.object(llm_client, "get_client", return_value=fake):
            llm_client.chamar_ia_json("system", "user", Diagnostico)
        self.assertEqual(create.call_args_list[1].kwargs["max_tokens"], 5600)


if __name__ == "__main__":
    unittest.main()


RATE_LIMIT_ERROR = (
    "Error code: 429 - {'error': {'message': 'Rate limit reached for model "
    "`openai/gpt-oss-120b` ... on tokens per minute (TPM): Limit 8000, Used 4713, "
    "Requested 4914. Please try again in 12.2025s.', 'type': 'tokens', "
    "'code': 'rate_limit_exceeded'}}"
)


class RateLimitWaitTests(unittest.TestCase):
    def test_the_wait_comes_from_the_message_plus_a_second(self):
        self.assertAlmostEqual(llm_client._rate_limit_wait(RATE_LIMIT_ERROR), 13.2025, places=3)

    def test_a_429_without_a_time_gets_a_default_wait(self):
        self.assertEqual(llm_client._rate_limit_wait("Error code: 429 - too many requests"), 20.0)

    def test_another_error_is_not_a_rate_limit(self):
        self.assertIsNone(llm_client._rate_limit_wait("Error code: 400 - bad json"))

    def test_the_wait_is_capped(self):
        long = "429 rate_limit_exceeded Please try again in 3600s."
        self.assertEqual(llm_client._rate_limit_wait(long), 60.0)


class RateLimitRetryTests(unittest.TestCase):
    def _call_json(self, side_effect):
        create = mock.Mock(side_effect=side_effect)
        fake = mock.Mock()
        fake.chat.completions.create = create
        with mock.patch.object(llm_client, "get_client", return_value=fake):
            with mock.patch.object(llm_client.time, "sleep") as sleep:
                result = llm_client.chamar_ia_json("system", "user", Diagnostico, 1400)
        return result, create, sleep

    def test_a_tpm_refusal_waits_and_retries(self):
        good = _response('{"falhas": []}')
        result, create, sleep = self._call_json([Exception(RATE_LIMIT_ERROR), good])
        self.assertEqual(result, {"falhas": []})
        self.assertEqual(create.call_count, 2)
        self.assertAlmostEqual(sleep.call_args.args[0], 13.2025, places=3)

    def test_it_gives_up_after_the_retries(self):
        with self.assertRaises(Exception):
            self._call_json([Exception(RATE_LIMIT_ERROR)] * 5)
        # _call_json já mocka o sleep: a desistência não pode custar 40s de espera real.

    def test_the_text_call_retries_too(self):
        # Foi aqui que o GovTokenEscrow parou: 4 achados confirmados e o reparo sem resposta.
        create = mock.Mock(side_effect=[Exception(RATE_LIMIT_ERROR), _response("contract A {}")])
        fake = mock.Mock()
        fake.chat.completions.create = create
        with mock.patch.object(llm_client, "get_client", return_value=fake):
            with mock.patch.object(llm_client.time, "sleep"):
                out = llm_client.chamar_ia_texto("system", "user")
        self.assertEqual(out, "contract A {}")
        self.assertEqual(create.call_count, 2)

    def test_the_text_call_still_returns_empty_on_another_error(self):
        create = mock.Mock(side_effect=Exception("Error code: 400 - bad request"))
        fake = mock.Mock()
        fake.chat.completions.create = create
        with mock.patch.object(llm_client, "get_client", return_value=fake):
            self.assertEqual(llm_client.chamar_ia_texto("system", "user"), "")
        self.assertEqual(create.call_count, 1)
