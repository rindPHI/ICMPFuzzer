from typing import List, Tuple, Optional, Set

from isla.derivation_tree import DerivationTree
from isla.language import SemPredEvalResult, StructuralPredicate, SemanticPredicate


def hex_to_bytes(hex_str: str) -> List[int]:
    return list(bytearray.fromhex(hex_str))


def int_to_hex(number: int, add_spaces=True) -> str:
    result = list(hex(number)[2:])
    if len(result) % 2 != 0:
        result.insert(0, "0")
    if add_spaces:
        for i in reversed(range(len(result))):
            if i > 0 and i % 2 == 0:
                result.insert(i, " ")
    return "".join(result)


def internet_checksum(
    _,
    header: DerivationTree,
    checksum_tree: DerivationTree,
) -> SemPredEvalResult:
    import re, string
    from pythonping import icmp
    from isla.helpers import srange
    from isla.parser import PEGParser

    if not header.is_complete():
        return SemPredEvalResult(None)

    checksum_grammar = {
        "<start>": ["<checksum>"],
        "<checksum>": ["<byte><byte>"],
        "<byte>": ["<zerof><zerof> "],
        "<zerof>": srange(string.digits + "ABCDEF"),
    }

    checksum_tree_str = re.sub(r"\s+", "", str(checksum_tree))
    if not len(checksum_tree_str) % 2 == 0:
        return SemPredEvalResult(False)

    zeroes = "".join("0" for _ in range(len(checksum_tree_str)))
    if str(checksum_tree).endswith(" "):
        zeroes += " "

    zero_checksum = ("<checksum>", [(zeroes, [])])

    header_wo_checksum = header.replace_path(
        header.find_node(checksum_tree),
        DerivationTree.from_parse_tree(zero_checksum),
    )

    header_bytes: Tuple[int] = tuple(reversed(hex_to_bytes(str(header_wo_checksum))))

    checksum_value = int_to_hex(icmp.checksum(header_bytes)).upper() + " "
    if len(checksum_value) < 6:
        assert len(checksum_value) == 3
        checksum_value = "00 " + checksum_value

    checksum_value_nospace = re.sub(r"\s+", "", checksum_value)
    if checksum_value_nospace == checksum_tree_str:
        return SemPredEvalResult(True)

    checksum_parser = PEGParser(checksum_grammar, start_symbol="<checksum>")
    new_checksum_tree = DerivationTree.from_parse_tree(
        list(checksum_parser.parse(checksum_value))[0]
    )

    if str(new_checksum_tree) == str(checksum_tree):
        return SemPredEvalResult(True)

    return SemPredEvalResult({checksum_tree: new_checksum_tree})


def predicates() -> Set[StructuralPredicate | SemanticPredicate]:
    return {
        SemanticPredicate("internet_checksum", 2, internet_checksum, binds_tree=False)
    }

