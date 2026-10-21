#!/usr/bin/env python3
"""Read-only, bounded HTTP + Cowrie evidence timeline. Never contacts indicators."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import heapq
import ipaddress
import json
from pathlib import Path
import re
import sqlite3
import time

MAX_LINE = 1024 * 1024
SECRET_KEYS = {'password', 'passwd', 'authorization', 'cookie'}


def timestamp(value):
    dt = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
    if dt.tzinfo is None:
        raise ValueError('timestamp has no timezone')
    return dt.astimezone(timezone.utc).isoformat()


def redact(obj):
    if isinstance(obj, dict):
        return {k: '[redacted]' if k.lower() in SECRET_KEYS else redact(v) for k,v in obj.items()}
    if isinstance(obj, list):
        return [redact(v) for v in obj]
    return obj


def http_events(path, limit, warnings):
    path = Path(path) / 'events.sqlite3'
    if not path.is_file():
        warnings.append('HTTP evidence database missing; HTTP coverage unknown')
        return []
    try:
        db = sqlite3.connect(path.resolve().as_uri()+'?mode=ro',uri=True,timeout=2)
        try:
            rows = db.execute('SELECT id,time,peer,metadata,raw_file,raw_sha256,raw_bytes FROM events ORDER BY time DESC LIMIT ?', (limit+1,)).fetchall()
        finally:
            db.close()
        if len(rows)>limit:
            warnings.append('HTTP event limit reached; only most recent events included')
        out=[]
        for event_id,stamp,peer,metadata,filename,digest,size in rows[:limit]:
            try:
                metadata=json.loads(metadata)
                source=json.loads(peer)
                ip=source[0] if isinstance(source,list) and source else None
                # Raw evidence remains intact; omit arbitrary headers from summary.
                out.append({'id':event_id,'time':timestamp(stamp),'protocol':'http','src_ip':ip,
                    'session':None,'event':'http.request','method':metadata.get('method'),
                    'target':metadata.get('target'),'signals':metadata.get('signals',[]),
                    'complete':metadata.get('complete'),'error':metadata.get('error'),
                    'bytes':size,'raw_file':filename,'sha256':digest})
            except (ValueError,TypeError,KeyError):
                warnings.append('Malformed HTTP record: '+str(event_id))
        return out
    except sqlite3.Error as exc:
        warnings.append('HTTP database unavailable: '+str(exc))
        return []


def cowrie_events(path, max_bytes, max_files, limit, warnings):
    folder=Path(path)/'log'/'cowrie'
    if not folder.is_dir():
        warnings.append('Cowrie log directory missing; SSH coverage unknown')
        return []
    files=sorted(folder.glob('cowrie.json*'),key=lambda p:p.stat().st_mtime,reverse=True)
    if not files:
        warnings.append('Cowrie JSON logs absent; SSH coverage unknown')
        return []
    if len(files)>max_files:
        warnings.append('Cowrie file limit reached; older rotations excluded')
    events=[]
    for file in files[:max_files]:
        try:
            if not file.is_file() or file.is_symlink():
                continue
            with file.open('rb') as f:
                size=f.seek(0,2)
                start=max(0,size-max_bytes)
                f.seek(start)
                if start:
                    warnings.append('Cowrie file truncated to bounded tail: '+file.name)
                    f.readline(MAX_LINE+1)  # skip a possibly partial first record
                while True:
                    offset=f.tell()
                    line=f.readline(MAX_LINE+1)
                    if not line:
                        break
                    if len(line)>MAX_LINE:
                        warnings.append('Oversized Cowrie line skipped: '+file.name)
                        while line and not line.endswith(b'\n'):
                            line=f.readline(MAX_LINE+1)
                        continue
                    if not line.endswith(b'\n'):
                        warnings.append('Partial final Cowrie line skipped: '+file.name)
                        continue
                    try:
                        obj=json.loads(line)
                        if not isinstance(obj,dict):
                            raise ValueError('not an event')
                        stamp=timestamp(obj['timestamp'])
                        event=str(obj['eventid'])
                    except (ValueError,KeyError,TypeError):
                        warnings.append('Malformed Cowrie event skipped: '+file.name+':'+str(offset))
                        continue
                    # Preserve session and original source evidence references.
                    item={'id':'cowrie:'+file.name+':'+str(offset), 'time':stamp,
                          'protocol':'ssh','src_ip':obj.get('src_ip'),
                          'session':obj.get('session'), 'event':event,
                          'evidence_file':file.name, 'evidence_offset':offset,
                          'details':obj}
                    # Keep only the newest bounded set while still reading session anchors.
                    events.append(item)
        except OSError as exc:
            warnings.append('Cowrie file unavailable: '+file.name+':'+str(exc))
    # Some Cowrie command records omit src_ip. Resolve only inside an observed
    # session with one consistent source; never borrow an IP across sessions.
    sources={}
    for e in events:
        if e['session'] and e['src_ip']:
            sources.setdefault(e['session'],set()).add(e['src_ip'])
    for e in events:
        found=sources.get(e['session'],set())
        if len(found)>1:
            e['source_conflict']=True
        if not e['src_ip'] and len(found)==1:
            e['src_ip']=next(iter(found))
            e['source_inferred_from_session']=True
    if len(events)>limit:
        warnings.append('Cowrie event limit reached; only most recent events included')
    return heapq.nlargest(limit,events,key=lambda e:e['time'])


def indicators(events):
    result={}
    for event in events:
        # Extract only from observed targets and command lines, not log formatting.
        fields=[event.get('target') or '',event.get('details',{}).get('input') or '',
                event.get('details',{}).get('url') or '']
        for field in fields:
            if not isinstance(field,str):
                continue
            for value in re.findall(r'(?:https?|ftp)://[^\s<>\x00-\x1f\x7f\"\']+',field):
                key=('url',value)
                result.setdefault(key,set()).add(event['id'])
            for candidate in re.findall(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])',field):
                try:
                    value=str(ipaddress.ip_address(candidate))
                except ValueError:
                    continue
                result.setdefault(('ipv4',value),set()).add(event['id'])
    return [{'type':kind,'value':value,'evidence_ids':sorted(ids)} for (kind,value),ids in sorted(result.items())]


def snapshot(args):
    warnings=[]
    events=http_events(args.http,args.limit,warnings)
    events+=cowrie_events(args.cowrie,args.max_log_bytes,args.max_files,args.limit,warnings)
    if args.ip:
        events=[e for e in events if e.get('src_ip')==args.ip]
    if args.session:
        events=[e for e in events if e.get('session')==args.session]
    if args.since:
        events=[e for e in events if e['time']>=args.since]
    events.sort(key=lambda e:(e['time'],e['id']))
    if len(events)>args.limit:
        events=events[-args.limit:]
        warnings.append('Combined event limit reached')
    result={'observed_at':datetime.now(timezone.utc).isoformat(),
            'coverage':'partial' if warnings else 'available_files_within_limits',
            'warnings':sorted(set(warnings)), 'event_count':len(events),
            'protocols':dict(Counter(e['protocol'] for e in events)),
            'correlation':'Same source IP and timing only; not attribution or proof of PHP exploitation.',
            'events':events}
    if args.indicators:
        result['indicators']=indicators(events)
    return result if args.show_credentials else redact(result)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--http',default='/data')
    p.add_argument('--cowrie',default='/cowrie')
    p.add_argument('--ip',type=lambda x:str(ipaddress.ip_address(x)))
    p.add_argument('--session')
    p.add_argument('--since',type=timestamp,help='ISO 8601 with timezone')
    p.add_argument('--limit',type=int,default=10000)
    p.add_argument('--max-log-bytes',type=int,default=8*1024*1024)
    p.add_argument('--max-files',type=int,default=8)
    p.add_argument('--indicators',action='store_true')
    p.add_argument('--show-credentials',action='store_true')
    p.add_argument('--follow',action='store_true',help='emit newly seen events as JSON lines')
    args=p.parse_args()
    if not 1<=args.limit<=100000 or not 1<=args.max_files<=32 or not 1<=args.max_log_bytes<=16*1024*1024:
        p.error('limit 1..100000, max-files 1..32, max-log-bytes 1..16777216')
    if not args.follow:
        print(json.dumps(snapshot(args),indent=2))
        return
    seen=set()
    try:
        while True:
            report=snapshot(args)
            print(json.dumps({'type':'coverage','observed_at':report['observed_at'],
                              'coverage':report['coverage'],'warnings':report['warnings']}),flush=True)
            current=set()
            for event in report['events']:
                current.add(event['id'])
                if event['id'] not in seen:
                    print(json.dumps(event),flush=True)
            seen=current
            time.sleep(2)
    except KeyboardInterrupt:
        pass


if __name__=='__main__':
    main()
