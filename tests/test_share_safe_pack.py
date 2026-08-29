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

if __name__=='__main__': unittest.main()
