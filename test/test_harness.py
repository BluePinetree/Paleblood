# SPDX-License-Identifier: GPL-2.0-or-later
"""tools/harness.py and verify.py compare on a synthetic image: no game data needed.

The image holds one function at offset 0 (PS4 address 0x400000):

    f(out): calls import 0 (via its GOT slot) with (7, &local); local += *glob_ptr;
            *out = local; glob2 = (uint32)local

Data page at 0x1000: got0 (import 0), glob = 0x100, glob_ptr -> glob (base-relative relocation),
glob2. A correct native replacement must give the same result, a broken one must not.
"""
import base64
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS = os.path.join(ROOT, 'tools')
sys.path.insert(0, TOOLS)
import verify  # noqa: E402

CODE = bytes.fromhex('534889fb4883ec10bf070000004889e6ff15ea0f0000488b0424488b0def0f0000'
                     '4803014889038905eb0f00004883c4105bc3')
# At 0x400800: return [rsp+8] + [rsp+16] + [rsp+24] (three stack arguments).
STACK_CODE = bytes.fromhex('488b442408' '4803442410' '4803442418' 'c3')
DATA = bytes.fromhex('0000000000000000000100000000000008100000000000000000000000000000')
SIZE = 0x1020

REPLACEMENT_C = r'''
#include <stdint.h>
typedef struct { uint32_t version; unsigned char *image; uint64_t image_size;
                 int (*install_hook)(uint64_t, uint64_t, const void *); } host_t;
static unsigned char *img;
int bbgame_init(const host_t *h) { img = h->image; return 0; }
typedef int (*import_fn)(int, uint64_t *);
void replacement(uint64_t *out)
{
    uint64_t local;
    (*(import_fn *)(img + 0x1000))(7, &local);
    local += **(uint64_t **)(img + 0x1010);
    BRANCH
    OUT_WRITE
    GLOBAL_WRITE
}
'''


def nid(name):
    digest = hashlib.sha1(name.encode() + bytes.fromhex('518d64a635ded8c1e6b039b1c3e55230')).digest()[:8][::-1]
    return base64.b64encode(digest).decode().rstrip('=').replace('/', '-')


def boot_image():
    """The synthetic executable: code (with the stack-argument function at 0x800) and a data page
    whose first word is the import's slot and whose word at +0x10 points at +0x8."""
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import ps4elf
    code = bytearray(0x1000)
    code[:len(CODE)] = CODE
    code[0x800:0x800 + len(STACK_CODE)] = STACK_CODE
    code[0x900:0x906] = bytes.fromhex('b807000000c3')
    code[0x910:0x912] = bytes.fromhex('ebfe')
    code[0x920:0x928] = bytes.fromhex('48c7c707000000c3')
    code[0x930:0x936] = bytes.fromhex('ba09000000c3')
    return ps4elf.build(
        segments=[(0, bytes(code), 0x1000, 5), (0x1000, DATA, 0x20, 6)],
        symbols=[(nid('testImport') + '#A#A', ps4elf.STT_FUNC, None)],
        relocations=[(0x1010, ps4elf.R_X86_64_RELATIVE, 0, 0x1008)],
        jump_slots=[(0x1000, ps4elf.R_X86_64_JUMP_SLOT, 1, 0)])


CASE = {
    'schema': 1, 'address': '0x00400000', 'id': 'synthetic', 'returns': 'void',
    'args': {'rdi': 'buf:out'},
    'buffers': {'out': {'size': 8}},
    'imports': [{'name': 'testImport', 'argc': 2, 'ret': 0,
                 'writes': [{'arg': 1, 'offset': 0, 'bytes': struct.pack('<Q', 0x1234).hex()}]}],
}


@unittest.skipUnless(sys.platform == 'linux' and shutil.which('cc'), 'needs Linux x86-64 and a C compiler')
class Harness(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.boot = os.path.join(self.d, 'eboot.elf')
        with open(self.boot, 'wb') as f:
            f.write(boot_image())
        self.case = os.path.join(self.d, 'case.json')
        with open(self.case, 'w') as f:
            json.dump(CASE, f)

    def tearDown(self):
        shutil.rmtree(self.d)

    def side(self, lib=None):
        return self.side_case(self.case, lib, '0x00400000')

    def side_case(self, case_path, lib=None, address='0x00400000'):
        cmd = [sys.executable, os.path.join(TOOLS, 'harness.py'), '--elf', self.boot,
               '--case', case_path, '--address', address]
        if lib:
            cmd += ['--replacement', 'replacement', '--lib', lib]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(r.stdout)

    def build(self, broken=False, mutation=None):
        src = os.path.join(self.d, 'r.c')
        with open(src, 'w') as f:
            source = REPLACEMENT_C.replace('BRANCH', 'local = local == 0x1334 ? 1 : local;' if mutation == 'branch' else '')
            source = source.replace('OUT_WRITE', '' if mutation == 'missing-write' else '*out = local ' + ('+ 1' if broken else '') + ';')
            source = source.replace('GLOBAL_WRITE',
                                    '*(uint16_t *)(img + 0x1018) = (uint16_t)local;' if mutation == 'narrow-write'
                                    else '*(uint32_t *)(img + 0x1018) = (uint32_t)local;')
            f.write(source)
        lib = os.path.join(self.d, f'r{int(broken)}-{mutation or "plain"}.so')
        subprocess.run(['cc', '-shared', '-fPIC', '-O2', '-o', lib, src], check=True)
        return lib

    def test_original_runs(self):
        r = self.side()
        self.assertEqual(r['calls'], [{'import': 'testImport', 'args': ['0x7', 'stack']}])
        self.assertIn({'addr': 'buf:out+0x0', 'bytes': '3413'}, r['writes'])
        self.assertIn({'addr': '0x00401018', 'bytes': '3413'}, r['writes'])
        self.assertTrue(all(v == 'kept' for v in r['preserved'].values()))

    def compare(self, broken):
        res = lambda r: {'schema': 1, 'address': '0x00400000', 'cases': [r]}
        return verify.compare(res(self.side()), res(self.side(self.build(broken))))

    def test_correct_replacement_matches(self):
        self.assertEqual(self.compare(False)['failed'], 0)

    def test_broken_replacement_fails(self):
        out = self.compare(True)
        self.assertEqual(out['failed'], 1)
        self.assertIn('buf:out+0x0', out['failures'][0]['diffs'][0])

    def test_mutation_matrix_rejects_branch_and_memory_write_errors(self):
        out = self.compare(False)
        self.assertEqual(out['failed'], 0)
        for mutation in ('branch', 'missing-write', 'narrow-write'):
            with self.subTest(mutation=mutation):
                case_path = self.case
                if mutation == 'narrow-write':
                    case = dict(CASE, memory=[{'addr': '0x00401018', 'bytes': 'aabbccdd'}])
                    case_path = os.path.join(self.d, 'narrow.json')
                    with open(case_path, 'w') as stream:
                        json.dump(case, stream)
                original = self.side_case(case_path)
                replacement = self.side_case(case_path, self.build(mutation=mutation))
                summary = verify.compare(
                    {'schema': 1, 'address': '0x00400000', 'cases': [original]},
                    {'schema': 1, 'address': '0x00400000', 'cases': [replacement]},
                )
                self.assertEqual(summary['failed'], 1)

    def test_wrong_return_mutation_is_detected_on_original_instructions(self):
        case = {'schema': 1, 'address': '0x00400900', 'id': 'return', 'returns': 'i32',
                'args': {}, 'buffers': {}, 'memory': [], 'imports': [], 'stubs': []}
        case_path = os.path.join(self.d, 'return.json')
        with open(case_path, 'w') as stream:
            json.dump(case, stream)
        source = os.path.join(self.d, 'return.c')
        library = os.path.join(self.d, 'return.so')
        with open(source, 'w') as stream:
            stream.write('#include <stdint.h>\n'
                         'typedef struct { uint32_t version; unsigned char *image; uint64_t image_size;\n'
                         'int (*install_hook)(uint64_t,uint64_t,const void *); } host_t;\n'
                         'int bbgame_init(const host_t *h) { (void)h; return 0; }\n'
                         'int replacement(void) { return 8; }\n')
        subprocess.run(['cc', '-shared', '-fPIC', '-O2', '-o', library, source], check=True)
        original = verify.run_side(self.boot, case_path, '0x00400900', None, None)
        replacement = verify.run_side(self.boot, case_path, '0x00400900', 'replacement', library)
        summary = verify.compare(
            {'schema': 1, 'address': case['address'], 'cases': [original]},
            {'schema': 1, 'address': case['address'], 'cases': [replacement]},
        )
        self.assertEqual(summary['failed'], 1)
        self.assertTrue(any('ret.rax' in item for item in summary['failures'][0]['diffs']))

    def test_opted_in_caller_saved_register_is_compared(self):
        case = {'schema': 1, 'address': '0x00400920', 'id': 'caller-saved', 'returns': 'void',
                'observe_registers': ['rdi'], 'args': {}, 'buffers': {}, 'memory': [],
                'imports': [], 'stubs': []}
        case_path = os.path.join(self.d, 'register.json')
        with open(case_path, 'w') as stream:
            json.dump(case, stream)
        original = self.side_case(case_path, address='0x00400920')
        self.assertEqual(original['registers']['rdi'], '0x7')
        self.assertEqual(original['observed_registers'], ['rdi'])
        case.update(address='0x00400930', observe_registers=['rdx'])
        with open(case_path, 'w') as stream:
            json.dump(case, stream)
        original = self.side_case(case_path, address='0x00400930')
        self.assertEqual(original['registers']['rdx'], '0x9')

    def test_original_instruction_timeout_is_bounded(self):
        case = {'schema': 1, 'address': '0x00400910', 'id': 'infinite-loop', 'returns': 'void',
                'args': {}, 'buffers': {}, 'memory': [], 'imports': [], 'stubs': []}
        case_path = os.path.join(self.d, 'timeout.json')
        with open(case_path, 'w') as stream:
            json.dump(case, stream)
        result = verify.run_side(self.boot, case_path, case['address'], None, None, timeout=1)
        self.assertEqual(result['fault'], 'timeout after 1 s')

    def test_run_counts_cases_with_repeated_ids(self):
        caps = os.path.join(self.d, 'caps')
        os.makedirs(caps)
        for n in ('a', 'b'):
            with open(os.path.join(caps, f'{n}.json'), 'w') as f:
                json.dump(CASE, f)            # both files carry id 'synthetic'
        lib = self.build(False)
        results = verify.run_cases(self.boot, caps, '0x00400000', 'replacement', lib)
        res = lambda side: {'schema': 1, 'address': '0x00400000', 'cases': results[side]}
        out = verify.compare(res('original'), res('replacement'))
        self.assertEqual((out['cases'], out['failed']), (2, 0))

    def test_capture_provenance_is_optional_but_bound_when_present(self):
        caps = os.path.join(self.d, 'caps')
        os.makedirs(caps)
        path = os.path.join(caps, 'capture.json')
        captured = dict(CASE, capture={'function': 'synthetic_function', 'run_id': 'test-run_1'})
        with open(path, 'w') as f:
            json.dump(captured, f)
        lib = self.build(False)
        results = verify.run_cases(self.boot, caps, '0x00400000', 'replacement', lib,
                                   function='synthetic_function')
        self.assertEqual(len(results['original']), 1)
        with self.assertRaisesRegex(verify.BadInput, 'records .+, not'):
            verify.run_cases(self.boot, caps, '0x00400000', 'replacement', lib,
                             function='different_function')
        captured['capture'] = {'function': 'synthetic_function', 'run_id': '../escape'}
        with open(path, 'w') as f:
            json.dump(captured, f)
        with self.assertRaisesRegex(verify.BadInput, 'invalid capture run_id'):
            verify.run_cases(self.boot, caps, '0x00400000', 'replacement', lib,
                             function='synthetic_function')

    def test_legacy_capture_without_provenance_replays(self):
        caps = os.path.join(self.d, 'caps')
        os.makedirs(caps)
        with open(os.path.join(caps, 'legacy.json'), 'w') as f:
            json.dump(CASE, f)
        results = verify.run_cases(self.boot, caps, '0x00400000', 'replacement', self.build(False),
                                   function='synthetic_function')
        self.assertEqual(len(results['original']), 1)

    def test_direct_harness_rejects_wrong_case_address(self):
        wrong = dict(CASE, address='0x00400800')
        with open(self.case, 'w') as f:
            json.dump(wrong, f)
        cmd = [sys.executable, os.path.join(TOOLS, 'harness.py'), '--elf', self.boot,
               '--case', self.case, '--address', '0x00400000']
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 3)
        self.assertIn('case is for 0x00400800', r.stderr)

    def test_stub_replaces_a_game_function(self):
        # Stub f itself at 0x400000 and call it through... the harness calls the stub directly.
        case = dict(CASE, stubs=[{'address': '0x00400000', 'ret': 5}], returns='i64', imports=[])
        with open(self.case, 'w') as f:
            json.dump(case, f)
        r = self.side()
        self.assertEqual(r['ret'], {'rax': '0x5'})
        self.assertEqual(r['calls'], [{'call': '0x00400000', 'args': []}])
        self.assertEqual(r['writes'], [])

    def test_series_entry_writes_one_value_per_call(self):
        # The function reads the first 8 bytes the import writes: the timeval's seconds.
        case = dict(CASE, imports=[{'name': 'testImport', 'argc': 2, 'ret': 0,
                                    'series': {'arg': 1, 'format': 'timeval_us',
                                               'values': [0x1234 * 1_000_000 + 7]}}])
        with open(self.case, 'w') as f:
            json.dump(case, f)
        r = self.side()
        self.assertIn({'addr': 'buf:out+0x0', 'bytes': '3413'}, r['writes'])
        self.assertNotIn('errors', r)

    def test_stack_arguments(self):
        case = dict(CASE, address='0x00400800', args={}, stack=['0x1', '0x20', '0x300'], returns='i64', imports=[])
        with open(self.case, 'w') as f:
            json.dump(case, f)
        cmd = [sys.executable, os.path.join(TOOLS, 'harness.py'), '--elf', self.boot, '--case', self.case,
               '--address', '0x00400800']
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        out = json.loads(r.stdout)
        self.assertEqual(out['ret'], {'rax': '0x321'})
        self.assertEqual(out['preserved']['rsp'], 'kept')

    def test_unscripted_import_is_reported(self):
        case = dict(CASE, imports=[])
        with open(self.case, 'w') as f:
            json.dump(case, f)
        self.assertIn('errors', self.side())


if __name__ == '__main__':
    unittest.main()
