import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'tools'))
import runtime_issues


class RuntimeIssueStatusTests(unittest.TestCase):
    def test_registered_symbols_are_read_from_runtime_sources(self):
        with tempfile.TemporaryDirectory() as root:
            directory = os.path.join(root, 'runtime', 'syslib')
            os.makedirs(directory)
            with open(os.path.join(directory, 'network.c'), 'w', encoding='utf-8') as source:
                source.write('''
                    // RT_SYSLIB("libSceNet", commented_line, fn);
                    /* RT_SYSLIB("libSceNet", commented_block, fn); */
                    RT_SYSLIB ( "libSceNet", sceNetHtonl, net_htonl );
                    RT_SYSLIB("libSceNet", sceNetHtons, net_htons);
                    RT_SYSLIB("libSceNet", sceNetNtohl, net_ntohl);
                    RT_SYSLIB("libSceNet", sceNetNtohs, net_ntohs);
                    RT_SYSLIB_UNRESOLVED("libSceNetCtl", sceNetCtlGetInfo, netctl_get_info);
                    RT_SYSLIB_UNRESOLVED("libSceNetCtl", sceNetCtlGetNatInfo, netctl_get_nat_info);
                ''')

            self.assertEqual({
                ('libSceNet', 'sceNetHtonl'),
                ('libSceNet', 'sceNetHtons'),
                ('libSceNet', 'sceNetNtohl'),
                ('libSceNet', 'sceNetNtohs'),
            }, runtime_issues.read_runtime_entries(root))

            self.assertNotIn(('libSceNetCtl', 'sceNetCtlGetInfo'), runtime_issues.read_runtime_entries(root))
            self.assertNotIn(('libSceNetCtl', 'sceNetCtlGetNatInfo'), runtime_issues.read_runtime_entries(root))

    def test_issue_counts_and_marks_registered_symbols(self):
        symbols = ('sceNetHtonl', 'sceNetHtons', 'sceNetNtohl', 'sceNetNtohs',
                   'sceNetCtlGetInfo', 'sceNetCtlGetNatInfo', 'sceNetSocket')
        rows = [{'library': 'libSceNet', 'symbol': symbol, 'implemented': 'no',
                 'kind': 'function', 'importers': {'eboot'}} for symbol in symbols]
        entries = {('libSceNet', symbol) for symbol in symbols[:4]}

        body = runtime_issues.issue(runtime_issues.GROUPS[-1], rows, entries)['body']

        self.assertIn('4 of 7 imported functions implemented', body)
        self.assertIn('### libSceNet (4 of 7)', body)
        for symbol in symbols[:4]:
            self.assertIn(f'- [x] `{symbol}`', body)
        for symbol in symbols[4:]:
            self.assertIn(f'- [ ] `{symbol}`', body)


if __name__ == '__main__':
    unittest.main()
