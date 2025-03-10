
import logging
from unittest import TestCase
import settings
import sys, traceback
import importlib
importlib.reload(sys)
sys.setdefaultencoding("utf-8")
import os
from AppCompatProcessor import main
import appDB
from test.auxTest import build_fake_DB

# Setup the logger
logger = logging.getLogger()
DB = None


class TestAppStatus(TestCase):
    fake_bd_num_hosts = 3
    testset1 = ''

    @classmethod
    def setup_class(self):
        # Build test dataset
        self.testset1 = build_fake_DB(self.fake_bd_num_hosts)

    @classmethod
    def teardown_class(self):
        # Remove temp dbs
        os.remove(self.testset1)

    def test_StatusAppCompat(self):
        with appDB.DBClass(self.testset1, settings.__version__) as DB:
            DB.appInitDB()
            conn = DB.appConnectDB()

            # Get host list
            (db_filenameFullPath2, db_version2, db_count2, num_instances2, num_entries2) = main([self.testset1, "status"])
            db_count_query = DB.CountHosts()

        # Check status count == db count
        self.assertEqual(db_count2, db_count_query, "test_StatusAmCache failed!")
        # Check status count == known host #
        self.assertEqual(db_count2, self.fake_bd_num_hosts, "test_StatusAmCache failed!")
        # Check reported path == known path
        self.assertEqual(db_filenameFullPath2, self.testset1, "test_StatusAmCache failed!")
        # Check entries count is with expected parameters
        self.assertTrue(num_entries2 > 400 * self.fake_bd_num_hosts and num_entries2 < 800 * self.fake_bd_num_hosts, "test_StatusAmCache failed!")
