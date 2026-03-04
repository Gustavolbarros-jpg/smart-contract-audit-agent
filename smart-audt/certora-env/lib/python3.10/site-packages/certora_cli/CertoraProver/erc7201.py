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

from Crypto.Hash import keccak


def calculate_keccak_hash(x: bytes) -> int:
    """
    Calculates the Keccak-256 hash of the input bytes and returns it as an integer.

    Args:
        x (bytes): The input bytes to be hashed.
    Returns:
        int: The Keccak-256 hash value as an integer.
    """
    k = keccak.new(digest_bits=256)
    k.update(x)
    return int(k.hexdigest(), base=16)

def erc7201(x: bytes) -> int:
    """
    Hashes the input bytes using the Keccak-256 algorithm and returns
    the result as an integer. The input is first hashed, then decremented
    by 1, and the resulting hash is used to compute the final hash.
    The final hash is masked to 256 bits and the last byte is cleared
    (set to zero).

    Args:
        x (bytes): The input bytes to be hashed.
    Returns:
        int: The final hash value as an integer.
    """
    return calculate_keccak_hash((calculate_keccak_hash(x) - 1).to_bytes(32, byteorder='big')) & (~0xff)
