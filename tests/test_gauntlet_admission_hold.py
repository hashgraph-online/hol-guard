from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from ci.gauntlet.control_plane.agent import Agent
from ci.gauntlet.control_plane.config import DEFAULTS,atomic_json


class HoldTests(unittest.TestCase):
    def test_hold_keeps_queued_work_and_observer_without_launching_a_job(self):
        with tempfile.TemporaryDirectory() as temp:
            state=Path(temp);(state/'private').mkdir()
            atomic_json(state/'private/hold-admissions.json',{'requested_at':time.time()})
            agent=Agent(dict(DEFAULTS),state)
            job={'id':'1'*16,'kind':'release','tag':'v3.48.0','sha':'a'*40,
                 'state':'queued','created_at':time.time()}
            agent.jobs=[job];agent.save(job)
            agent.discover=Mock(side_effect=agent.stop.set)
            agent.worker=Mock()
            agent.snapshot.update(deployment={'status':'installed'},
                host={'disk_free':60*1024**3,'checked_at':time.time()},
                vm={'status':'running','memory_total':16*1024**3,'memory_available':15*1024**3,
                    'disk_total':46*1024**3,'disk_free':30*1024**3,'checked_at':time.time()})
            with patch('ci.gauntlet.control_plane.agent.threading.Thread') as thread, \
                 patch('ci.gauntlet.control_plane.agent.signal.signal'):
                agent.run()
            self.assertTrue(agent.snapshot['admissions_held'])
            self.assertEqual(job['state'],'queued')
            agent.worker.assert_not_called()
            self.assertEqual(thread.call_count,1)  # Telemetry stays available.
