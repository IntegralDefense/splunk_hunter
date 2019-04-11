#!/usr/bin/env python3

import argparse
from configparser import ConfigParser
from datetime import datetime, timedelta
import glob
import logging
import logging.config
import os
import os.path
from queue import Queue, Empty
import re
import signal
import sys
import threading
import time
import traceback

from ace_api import Alert

# pip3 install splunklib
import splunklib

# pip3 install pytz
import pytz

# custom ConfigParser to keep case sensitivity
class CaseConfigParser(ConfigParser):
    def optionxform(self, optionstr):
        return optionstr

# global variables
BASE_DIR = None
RULES_DIR = [ ]
CONFIG = None

# set to True if running in daemon (scheduled) mode
DAEMON_MODE = False

# the amount of time we adjust for when running in daemon mode
GLOBAL_TIME_OFFSET = None

# the timezone we convert to when we specify time ranges
TIMEZONE = None

# utility functions

def report_error(message):
    logging.error(message)
    traceback.print_exc()

    try:
        output_dir = 'error_reporting'
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        with open(os.path.join(output_dir, datetime.now().strftime('%Y-%m-%d:%H:%M:%S.%f')), 'w') as fp:
            fp.write(message)
            fp.write('\n\n')
            fp.write(traceback.format_exc())

    except Exception as e:
        traceback.print_exc()

class SearchDaemon(object):
    """Executes a SearchManager in the background according to the schedules defined in the search definitions."""
    def __init__(self):
        self.shutdown = False
        self.search_manager = None
        self.thread = None
        self.thread_lock = threading.RLock()
        self.execution_slots = threading.Semaphore(CONFIG['global'].getint('max_searches'))

        # list of searches we manage
        self.managed_searches = []

    def start(self):
        self.thread = threading.Thread(target=self.run, name="SearchDaemon")
        self.thread.start()

        self.config_thread = threading.Thread(target=self.watch_config, name="SearchDaemon - config")
        self.config_thread.daemon = True
        self.config_thread.start()

    def stop(self):
        logging.info("daemon stopping...")
        self.shutdown = True

        try:
            # release anything blocking on the slots
            self.execution_slots.release()
        except:
            pass

        self.wait()

    def run(self):
        while not self.shutdown:
            try:
                self.execute()
            except Exception as e:
                report_error("uncaught exception: {0}".format(str(e)))
                time.sleep(1)

    def wait(self):
        self.thread.join()

    def execute(self):
        while not self.shutdown:
            # get a local copy of the list to use
            with self.thread_lock:
                managed_searches = self.managed_searches[:]

            for search in self.managed_searches:
                # skip searches that are disabled
                if not search.config['rule'].getboolean('enabled'):
                    continue
                # skip if it's already executing
                if search.executing:
                    continue

                # we store the time it last executed in a file
                if search.schedule_ready():
                    # wait for a slot to become ready (blocking)
                    acquire_start_time = datetime.now()
                    self.execution_slots.acquire()
                    acquire_end_time = datetime.now()
                    with open(os.path.join(BASE_DIR, 'logs', 'acquire_time_log'), 'a') as fp:
                        fp.write("{0}\t{1}\t{2}\r\n".format(search.search_name, acquire_start_time, acquire_end_time - acquire_start_time))

                    # make sure we're not shutting down
                    if self.shutdown:
                        return

                    self.execute_search(search)

            time.sleep(1.0)

    def watch_config(self):
        while True:
            try:
                self.load_searches()
            except Exception as e:
                report_error("uncaught exception when loading searches: {0}".format(str(e)))

            time.sleep(5)

    def load_searches(self):
        # add any new searches
        for rules_dir in RULES_DIR:
            for search_rule in glob.glob('{}/*.ini'.format(rules_dir)):
                search_name, _ = os.path.splitext(os.path.basename(search_rule))
                if search_name in [x.search_name for x in self.managed_searches]:
                    continue
                        
                logging.info("loading search {}".format(search_name))
                search = SplunkSearch(rules_dir, search_name)
                with self.thread_lock:
                    self.managed_searches.append(search)

        # remove any searches that no longer exists
        missing_searches = []
        for search in self.managed_searches:
            if not os.path.exists(search.config_path):
                logging.warning("search {0} deleted ({1})".format(search.search_name, search.config_path))
                missing_searches.append(search)

        with self.thread_lock:
            for search in missing_searches:
                self.managed_searches.remove(search)

        # refresh all loaded searches
        for search in self.managed_searches:
            search.refresh_configuration()

    def execute_search(self, search):
        # spin off a thread to execute the search in
        t = threading.Thread(target=self._execute_search, name=search.search_name, args=(search,))
        t.daemon = True
        t.start()

    def _execute_search(self, search):
        try:
            search.execute()
        except Exception as e:
            report_error("uncaught exception when executing search {0}: {1}".format(search.search_name, str(e)))
        finally:
            self.execution_slots.release()

class SplunkSearch(object):
    def __init__(self, rules_dir, search_name, submit_alert=True, print_alert_details=False):
        self.rules_dir = rules_dir
        self.search_name = search_name
        self.submit_alert = submit_alert
        self.print_alert_details = print_alert_details
        self.config_path = os.path.join(self.rules_dir, '{}.ini'.format(search_name))
        self.last_executed_path = os.path.join(BASE_DIR, 'var', '{}.last_executed'.format(search_name))
        self.config = CaseConfigParser()
        self.config_timestamp = None

        # set to True in daemon mode when the search is executing
        self.executing = False

        self.refresh_configuration()

    def refresh_configuration(self):
        current_config_timestamp = os.path.getmtime(self.config_path)
        if current_config_timestamp != self.config_timestamp:
            logging.info("loading configuration for {0} from {1}".format(self.search_name, self.config_path))
            self.config_timestamp = current_config_timestamp

            if not os.path.exists(self.config_path):
                logging.warning("file {0} does not exist".format(self.config_path))
                return

            if len(self.config.read(self.config_path)) < 1:
                raise Exception("unable to read configuration file {0}".format(self.config_path))

    @property
    def last_executed_time(self):
        """Returns the last time this search was executed in daemon mode as a float value (epoch), or None if the search has not been executed."""
        try:
            with open(self.last_executed_path, 'r') as fp:
                return float(fp.read())
        except:
            return None

    @last_executed_time.setter
    def last_executed_time(self, value):
        assert isinstance(value, float)

        with open(self.last_executed_path, 'w') as fp:
            fp.write(str(value))

    def schedule_ready(self):
        """Returns True if this search need to be executed according to the schedule."""
        # does this search have a specified run time?
        now = datetime.now()

        if 'run_time' in self.config['rule']:
            # so then the next time this should run will be today at the specified timespec
            next_runtime = now
            hour, minute, second = self.config['rule']['run_time'].split(':')
            next_runtime = next_runtime.replace(hour=int(hour), minute=int(minute), second=int(second), microsecond=0)

            # have we already ran this report today?
            if self.last_executed_time is not None and datetime.fromtimestamp(self.last_executed_time) >= next_runtime:
                return False

            # is it time to run this report then?
            if now > next_runtime:
                return True

            # otherwise it is not time yet
            return False

        # if the search does not specify a runtime then we use the frequency
        # have we not ran this ever before?
        if self.last_executed_time is None:
            return True
            
        return datetime.now() > datetime.fromtimestamp(self.last_executed_time) + splunklib.create_timedelta(self.config['rule']['frequency'])

    def is_temporal_field(self, field):
        """Returns True if the given field is a temporal field according to the configuration."""
        try:
            return field in self.config['temporal_fields'] and self.config['temporal_fields'].getboolean(field)
        except KeyError:
            return False

    def get_field_directives(self, field):
        """Returns a list of directives for the given field (or empty list if none are defined.)"""
        try:
            return [x.strip() for x in self.config['directives'][field].split(',')]
        except KeyError:
            return []

    def execute(self, *args, **kwargs):
        start_time = None
        end_time = None

        try:
            self.executing = True
            start_time = datetime.now()
            self._execute(*args, **kwargs)
        finally:
            self.executing = False
            end_time = datetime.now()
            with open(os.path.join(BASE_DIR, 'logs', '{0}.stats'.format(self.search_name)), 'a') as fp:
                fp.write('{0}\t{1}\r\n'.format(start_time, end_time - start_time))

    def _execute(self, earliest=None, latest=None, use_index_time=None, max_result_count=None):
        now = time.mktime(time.localtime())

        if earliest is None:
            earliest = self.config['rule']['earliest']
            if DAEMON_MODE and self.config['rule'].getboolean('full_coverage') and self.last_executed_time:
                earliest = datetime.fromtimestamp(self.last_executed_time)
                # are we adjusting all the times backwards?
                if GLOBAL_TIME_OFFSET is not None:
                    logging.debug("adjusting timespec by {0}".format(GLOBAL_TIME_OFFSET))
                    earliest = earliest - GLOBAL_TIME_OFFSET
                if TIMEZONE:
                    target_earliest = earliest.astimezone(TIMEZONE)
                    logging.debug(f"converted {earliest} to {target_earliest}")
                    earliest = target_earliest
                earliest = earliest.strftime('%m/%d/%Y:%H:%M:%S')
                logging.debug("using earliest from last execution time {0}".format(earliest))

        if latest is None:
            latest = self.config['rule']['latest']
            if DAEMON_MODE and self.config['rule'].getboolean('full_coverage') and self.last_executed_time:
                latest = datetime.fromtimestamp(now)
                # are we adjusting all the times backwards?
                if GLOBAL_TIME_OFFSET is not None:
                    logging.debug("adjusting timespec by {0}".format(GLOBAL_TIME_OFFSET))
                    latest = latest - GLOBAL_TIME_OFFSET
                if TIMEZONE:
                    target_latest = latest.astimezone(TIMEZONE)
                    logging.debug(f"converted {latest} to {target_latest}")
                    latest = target_latest
                latest = latest.strftime('%m/%d/%Y:%H:%M:%S')

        if use_index_time is None:
            use_index_time = self.config['rule'].getboolean('use_index_time')

        if use_index_time:
            time_spec = '_index_earliest = {0} _index_latest = {1}'.format(earliest, latest)
        else:
            time_spec = 'earliest = {0} latest = {1}'.format(earliest, latest)

        if max_result_count is None:
            max_result_count = self.config['rule'].getint('max_result_count')

        with open(self.config['rule']['search'], 'r') as fp:
            search_text = fp.read()
            # comments in the search files are lines that start with #
            search_text = re.sub(r'^\s*#.*$', '', search_text, count=0, flags=re.MULTILINE)
            # make sure the time spec formatter is available
            # this should really be done at load time...
            if '{time_spec}' not in search_text:
                logging.fatal("missing {{time_spec}} formatter in rule {0}".format(self.search_name))
                sys.exit(1)
            else:
                search_text = search_text.format(time_spec=time_spec)

            # run the includes you might have
            while True:
                m = re.search(r'<include:([^>]+)>', search_text)
                if not m:
                    break
                
                include_path = os.path.join(BASE_DIR, m.group(1))
                if not os.path.exists(include_path):
                    logging.fatal("rule {0} included file {1} does not exist".format(self.search_name, include_path))
                    sys.exit(1)

                with open(include_path, 'r') as fp:
                    search_text = search_text.replace(m.group(0), fp.read().strip())

            # put it all on one line for splunk
            # we don't *need* to do this except for keeping the logs clean
            search_text = re.sub(r'\n', ' ', search_text, count=0)

        logging.info("executing search {}".format(self.search_name))
        logging.debug("search {} search_text {}".format(self.search_name, search_text))

        searcher = splunklib.SplunkQueryObject(
            uri=CONFIG['splunklib']['uri'],
            username=CONFIG['splunklib']['username'],
            password=CONFIG['splunklib']['password'],
            max_result_count=max_result_count)
        search_result = searcher.query(search_text)

        if not search_result:
            logging.error("search failed for {0}".format(self.search_name))
            return False

        if searcher.json() is None:
            logging.error("search {} returned no results (usually indicates an issue with the search)".format(
                          self.search_name))
            return False

        # record the fact that we ran it
        if DAEMON_MODE:
            self.last_executed_time = now

        # group the events for alerting
        # if there is no grouping then all are individual events
        event_grouping = {} # key = group_by value
        has_group_by = 'group_by' in self.config['rule']
        unique_id = 0

        for event in searcher.json():
            if has_group_by:
                group_by_value = event[self.config['rule']['group_by']]
                if isinstance(group_by_value, list):
                    group_by_value = ' '.join(group_by_value)
            else:
                group_by_value = str(unique_id)
                unique_id += 1

            if group_by_value not in event_grouping:
                event_grouping[group_by_value] = []

            event_grouping[group_by_value].append(event)

        for key_value in event_grouping.keys():
            alert_title = self.config['rule']['name']
            if key_value != '':
                alert_title = '{} - {}'.format(alert_title, key_value)

            # alert type defaults to splunk but you can override
            alert_type = 'splunk'
            if 'type' in self.config['rule']:
                alert_type = self.config['rule']['type']

            alert = Alert(
                tool='splunk',
                tool_instance='splunk_detection',
                alert_type=alert_type,
                desc=alert_title,
                event_time=time.strftime("%Y-%m-%d %H:%M:%S"),
                details=event_grouping[key_value],
                name=self.config['rule']['name'],
                company_name=CONFIG['ace']['company_name'],
                company_id=CONFIG['ace'].getint('company_id'))

            # extract tags
            if 'tags' in self.config['rule']:
                for tag in self.config['rule']['tags'].split(','):
                    alert.add_tag(tag)

            # extract observables
            for event in event_grouping[key_value]:
                # is this observable type a temporal type?
                o_time = event['_time'] if '_time' in event else None
                if o_time is not None:
                    m = re.match(r'^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})\.[0-9]{3}[-+][0-9]{2}:[0-9]{2}$', o_time)
                    if not m:
                        logging.error("_time field does not match expected format: {0}".format(o_time))
                    else:
                        # reformat this time for ACE
                        o_time = '{0}-{1}-{2} {3}:{4}:{5}'.format(
                            m.group(1),
                            m.group(2),
                            m.group(3),
                            m.group(4),
                            m.group(5),
                            m.group(6))

                for o_field in self.config['observable_mapping'].keys():
                    if o_field not in event:
                        logging.debug("field {0} does not exist in event".format(o_field))
                        continue

                    o_type = self.config['observable_mapping'][o_field]
                    if isinstance(event[o_field], list):
                        o_values = event[o_field]
                    else:
                        o_values = [ event[o_field] ]

                    for o_value in o_values:
                        # ignore values that are None, empty string or a single -
                        if o_value is None:
                            continue

                        # make sure this is a string
                        if not isinstance(o_value, str):
                            o_value = str(o_value)

                        if o_value.strip() == '' or o_value.strip() == '-':
                            continue

                        alert.add_observable(o_type, 
                                             o_value, 
                                             o_time if self.is_temporal_field(o_field) else None, 
                                             directives=self.get_field_directives(o_field))

            try:
                logging.info("submitting alert {}".format(alert.description))
                if self.submit_alert:
                    alert.submit(CONFIG['ace']['uri'], CONFIG['ace']['key'], ssl_verification=CONFIG['ace']['ca_path'])
                else:
                    if self.print_alert_details:
                        print(str(alert))
                    else:
                        print(alert.description)
            except Exception as e:
                logging.error("unable to submit alert {}: {}".format(alert, str(e)))
                #report_error("unable to submit alert {}: {}".format(alert, e))

            logging.debug(str(alert))

        return search_result

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description="Splunk Hunter")
    parser.add_argument('-b', '--base-directory', required=False, default=None, dest='base_dir',
        help="Path to the base directory of the Splunk Detection tool. "
        "Defaults to current working directory. "
        "Override with SPLUNK_DETECTION environment variable.")
    parser.add_argument('-c', '--config', required=False, default='etc/config.ini', dest='config_path',
        help="Path to configuration file.  Defaults to etc/config.ini")
    parser.add_argument('--logging-config', required=False, default='etc/logging.ini', dest='logging_config',
        help="Path to logging configuration file.  Defaults to etc/logging.ini")
    parser.add_argument('-r', '--rules-dir', required=False, dest='rules_dir', action='append', default=[],
        help="Path to rules directory. More than one can be specified. Defaults to rules/")

    parser.add_argument('-d', '--daemon', required=False, default=False, action='store_true', dest='daemon',
        help="Start as daemon running automated searches.  Defaults to running individual searches as specified.")
    parser.add_argument('--background', required=False, default=False, action='store_true', dest='background',
        help="Run the background as a service.  Only applies to --daemon.")
    parser.add_argument('-k', '--kill', required=False, default=False, action='store_true', dest='kill',
        help="Kill a running daemon.")

    parser.add_argument('--earliest', required=False, default=None, dest='earliest',
        help="""Replace configuration specific earliest time.  Time spec absolute format is MM/DD/YYYY:HH:MM:SS
                NOTE: The time specified here will default to the timezone configured for the splunk account.
                Any timezone settings in the configuration are ignored.""")
    parser.add_argument('--latest', required=False, default=None, dest='latest',
        help="""Replace configuration specific latest time.  Time spec absolute format is MM/DD/YYYY:HH:MM:SS
                NOTE: The time specified here will default to the timezone configured for the splunk account.
                Any timezone settings in the configuration are ignored.""")
    parser.add_argument('-i', '--use-index-time', required=False, default=None, action='store_true', dest='use_index_time',
        help="Use __index time specs instead.")
    parser.add_argument('--exact-name', default=False, action='store_true', dest='exact_name',
        help="Match the exact name of the rule instead of a partial match.")
    parser.add_argument('-p', '--print-alerts', default=False, action='store_true', dest='print_alerts',
        help="Print the alerts that would be generated instead of sending them to ACE.")
    parser.add_argument('--print-alert-details', default=False, action='store_true', dest='print_alert_details',
        help="Valid only with the -p option -- prints the details of the generated alerts instead of just the description.")

    parser.add_argument("searches", nargs=argparse.REMAINDER, help="One or more searches to execute.")

    args = parser.parse_args()

    # initialize environment

    if 'SPLUNK_DETECTION' in os.environ:
        BASE_DIR = os.environ['SPLUNK_DETECTION']
    if args.base_dir:
        BASE_DIR = args.base_dir
    if not BASE_DIR:
        BASE_DIR = os.getcwd()

    try:
        os.chdir(BASE_DIR)
    except Exception as e:
        sys.stderr.write("ERROR: unable to cd into {0}: {1}\n".format(
            BASE_DIR, str(e)))
        sys.exit(1)

    # make sure all the directories exists that need to exist
    for path in [os.path.join(BASE_DIR, x) for x in ['error_reporting', 'logs', 'var']]:
        if not os.path.isdir(path):
            try:
                os.mkdir(path)
            except Exception as e:
                sys.stderr.write("ERROR: cannot create directory {0}: {1}\n".format(
                    path, str(e)))
                sys.exit(1)

    # remove proxy if it's set
    if 'http_proxy' in os.environ:
        del os.environ['http_proxy']
    if 'https_proxy' in os.environ:
        del os.environ['https_proxy']

    # load lib/ onto the python path
    sys.path.append('lib')


    if args.kill:
        daemon_path = os.path.join(BASE_DIR, 'var', 'daemon.pid')
        if os.path.exists(daemon_path):
            with open(daemon_path, 'r') as fp:
                daemon_pid = int(fp.read())

            os.kill(daemon_pid, signal.SIGKILL)
            print("killed pid {0}".format(daemon_pid))

            try:
                os.remove(daemon_path)
            except Exception as e:
                sys.stderr.write("ERROR: unable to delete {0}: {1}\n".format(daemon_path, str(e)))

            sys.exit(0)
        else:
            print("WARNING: no running instance available to kill")
            sys.exit(0)
    
    # are we running as a deamon/
    if args.daemon and args.background:

        pid = None

        # http://code.activestate.com/recipes/278731-creating-a-daemon-the-python-way/
        try:
            pid = os.fork()
        except OSError as e:
            logging.fatal("{0} ({1})".format(e.strerror, e.errno))
            sys.exit(1)

        if pid == 0:
            os.setsid()

            try:
                pid = os.fork()
            except OSError as e:
                logging.fatal("{0} ({1})".format(e.strerror, e.errno))
                sys.exit(1)

            if pid > 0:
                # write the pid to a file
                with open(os.path.join(BASE_DIR, 'var', 'daemon.pid'), 'w') as fp:
                    fp.write(str(pid))

                os._exit(0)
        else:
            os._exit(0)

        import resource
        maxfd = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
        if (maxfd == resource.RLIM_INFINITY):
            maxfd = MAXFD

            for fd in range(0, maxfd):
                try:
                    os.close(fd)
                except OSError:   # ERROR, fd wasn't open to begin with (ignored)
                    pass

        if (hasattr(os, "devnull")):
            REDIRECT_TO = os.devnull
        else:
            REDIRECT_TO = "/dev/null"

        os.open(REDIRECT_TO, os.O_RDWR)
        os.dup2(0, 1)
        os.dup2(0, 2)

    # initialize logging
    try:
        logging.config.fileConfig(args.logging_config)
    except Exception as e:
        sys.stderr.write("ERROR: unable to load logging config from {0}: {1}".format(
            args.logging_config, str(e)))
        sys.exit(1)

    # load configuration
    CONFIG = CaseConfigParser()
    try:
        CONFIG.read(args.config_path)
    except Exception as e:
        logging.fatal("unable to load configuration from {0}: {1}".format(
            args.config_path, str(e)))
        sys.exit(1)

    if args.rules_dir:
        RULES_DIR = args.rules_dir
        
    RULES_DIR = [os.path.join(BASE_DIR, _dir) for _dir in RULES_DIR]

    if CONFIG['global']['global_time_offset'] != '':
        hours, minutes, seconds = [int(x) for x in CONFIG['global']['global_time_offset'].split(':')]
        GLOBAL_TIME_OFFSET = timedelta(hours=hours, minutes=minutes, seconds=seconds)
        logging.debug("using global time delta {0}".format(GLOBAL_TIME_OFFSET))

    if CONFIG['global']['timezone']:
        TIMEZONE = pytz.timezone(CONFIG['global']['timezone'])
        logging.debug(f"using timezone {TIMEZONE}")

    if args.daemon:
        DAEMON_MODE = True
        daemon = SearchDaemon()
        daemon.start()

        try:
            daemon.wait()
        except KeyboardInterrupt:
            daemon.stop()
            daemon.wait()

        sys.exit(0)

    # otherwise we run each search by itself
    if len(args.searches) < 1:
        logging.fatal("Specify which searches you want to run.")
        sys.exit(1)

    search_object = None

    try:
        for search_name in args.searches:
            for rules_dir in RULES_DIR:
                glob_pattern = '{}/*.ini'.format(rules_dir)
                if not args.exact_name:
                    glob_pattern = '{}/*{}*.ini'.format(rules_dir, search_name)

                for search_result in glob.glob(glob_pattern):
                    if args.exact_name:
                        if search_name != os.path.basename(search_result)[:-4]:
                            continue

                    search_name, _ = os.path.splitext(os.path.basename(search_result))
                    search_object = SplunkSearch(rules_dir, search_name, submit_alert=not args.print_alerts, print_alert_details=args.print_alert_details)
                    search_object.execute(earliest=args.earliest, latest=args.latest, use_index_time=args.use_index_time)

    except KeyboardInterrupt:
        pass
