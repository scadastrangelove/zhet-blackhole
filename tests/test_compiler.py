from pathlib import Path

from blackhole.compiler.corpus_to_pack import compile_pack


def test_compile_public_cases_pack(tmp_path: Path):
    input_path = Path(__file__).resolve().parents[1] / 'data' / 'public_cases_v1.jsonl'
    output_path = tmp_path / 'compiled.yaml'
    result = compile_pack(input_path, output_path, 'test-pack')
    assert output_path.exists()
    assert result['profiles_total'] > 0



def test_compile_second_order_merged_corpus_pack(tmp_path: Path):
    input_path = Path(__file__).resolve().parents[1] / 'data' / 'public_cases_v1_plus_secondorder_v4.jsonl'
    output_path = tmp_path / 'compiled-v4.yaml'
    result = compile_pack(input_path, output_path, 'test-pack-v4')
    assert output_path.exists()
    assert result['profiles_total'] >= 160
