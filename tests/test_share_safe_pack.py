import tempfile, unittest
from pathlib import Path
from share_safe_pack import scan, redact_copy

class T(unittest.TestCase):
    def test_find_and_redact(self):
        d=Path(tempfile.mkdtemp()); p=d/'note.md'
        p.write_text('mail me test@example.com\nAPI_KEY=abcdefghijklmnop\nTODO later\n/home/jurio/demo')
        r=scan(d)
        self.assertGreaterEqual(r['counts']['email'],1)
        self.assertGreaterEqual(r['counts']['secret_like'],1)
        out=Path(tempfile.mkdtemp())/'safe'
        self.assertEqual(redact_copy(d,out),1)
        text=(out/'note.md').read_text()
        self.assertNotIn('test@example.com',text)
        self.assertIn('<redacted:email>',text)

    def test_redact_output_inside_source_is_rejected(self):
        d=Path(tempfile.mkdtemp()); (d/'note.md').write_text('test@example.com')
        with self.assertRaisesRegex(ValueError, 'outside the source directory'):
            redact_copy(d,d/'safe')
        self.assertFalse((d/'safe').exists())

    def test_redact_output_cannot_overwrite_source_file(self):
        d=Path(tempfile.mkdtemp()); p=d/'note.md'; p.write_text('test@example.com')
        with self.assertRaisesRegex(ValueError, 'overwrite the source file'):
            redact_copy(p,p)
        self.assertEqual(p.read_text(),'test@example.com')

    def test_symlinked_file_outside_root_is_skipped(self):
        d=Path(tempfile.mkdtemp())
        outside=Path(tempfile.mktemp(suffix='.md'))
        outside.write_text('API_KEY=outside-secret-value\n')
        (d/'linked.md').symlink_to(outside)
        report=scan(d)
        self.assertEqual(report['files'],0)
        self.assertEqual(report['findings'],[])
        out=Path(tempfile.mkdtemp())/'safe'
        self.assertEqual(redact_copy(d,out),0)
        self.assertFalse((out/'linked.md').exists())

    def test_official_github_token_prefixes_are_detected_and_redacted(self):
        prefixes=['ghp_','github_pat_','gho_','ghu_','ghs_','ghr_']
        d=Path(tempfile.mkdtemp()); p=d/'tokens.txt'
        p.write_text('\n'.join(prefix+'SyntheticTokenValue1234567890' for prefix in prefixes))
        report=scan(d)
        self.assertEqual(report['counts']['secret_like'],len(prefixes))
        out=Path(tempfile.mkdtemp())/'safe'
        self.assertEqual(redact_copy(d,out),1)
        text=(out/'tokens.txt').read_text()
        for prefix in prefixes:
            self.assertNotIn(prefix,text)
        self.assertEqual(text.count('<redacted:secret_like>'),len(prefixes))

    def test_dotenv_files_in_folder_are_scanned_and_redacted(self):
        d=Path(tempfile.mkdtemp())
        (d/'.env').write_text('API_KEY=syntheticvalue1234567890\n')
        (d/'.env.local').write_text('TOKEN=syntheticvalue1234567890\n')
        report=scan(d)
        paths={Path(f['path']).name for f in report['findings'] if f['kind']=='secret_like'}
        self.assertEqual(paths,{'.env','.env.local'})
        out=Path(tempfile.mkdtemp())/'safe'
        self.assertEqual(redact_copy(d,out),2)
        for name in ('.env','.env.local'):
            self.assertEqual((out/name).read_text().strip(),'<redacted:secret_like>')

    def test_unreadable_text_candidate_is_reported_not_silently_skipped(self):
        d=Path(tempfile.mkdtemp()); p=d/'broken.txt'
        p.write_bytes(b'\xff\xfe\xfa')
        report=scan(d)
        self.assertEqual(report['files'],1)
        self.assertEqual(report['counts']['scan_error'],1)
        self.assertEqual(len(report['findings']),1)
        finding=report['findings'][0]
        self.assertEqual(finding['kind'],'scan_error')
        self.assertEqual(Path(finding['path']).name,'broken.txt')
        self.assertIn('UnicodeDecodeError',finding['preview'])

if __name__=='__main__': unittest.main()
