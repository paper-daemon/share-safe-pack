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

if __name__=='__main__': unittest.main()
