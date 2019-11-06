import requests
import json
import os, time, sys
import logging

CHROME_WIN_UA = 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.87 Safari/537.36'

class Reporter():
    base_url = 'https://instagram.com/'
    login_url = base_url + 'accounts/login/ajax/'
    logout_url = base_url + 'accounts/logout/'
    report_user_url = base_url + '/user/{0}/report/{1}/'
    report_media_url = base_url + '/media/{0}/report/{1}/'
    STORIES_URL = base_url + 'graphql/query/?query_hash=45246d3fe16ccc6577e0bd297a5db1ab&variables=%7B%22reel_ids%22%3A%5B%22{0}%22%5D%2C%22tag_names%22%3A%5B%5D%2C%22location_ids%22%3A%5B%5D%2C%22highlight_reel_ids%22%3A%5B%5D%2C%22precomposed_overlay%22%3Afalse%7D'
    STORIES_UA = 'Instagram 52.0.0.8.83 (iPhone; CPU iPhone OS 11_4 like Mac OS X; en_US; en-US; scale=2.00; 750x1334) AppleWebKit/605.1.15'


    def __init__(self, **kwargs):
        default_attr = dict(username='', usernames=[], filename=None,
                            login_user=None, login_pass=None,
                            followings_input=False, followings_output='profiles.txt',
                            destination='./', logger=None, retain_username=False, interactive=False,
                            quiet=False, maximum=0, media_metadata=False, profile_metadata=False, latest=False,
                            latest_stamps=False, cookiejar=None,
                            media_types=['image', 'video', 'story-image', 'story-video'],
                            tag=False, location=False, search_location=False, comments=False,
                            verbose=0, include_location=False, filter=None, proxies={}, no_check_certificate=False,
                                                        template='{urlname}', log_destination='')

        allowed_attr = list(default_attr.keys())
        default_attr.update(kwargs)
        
        for key in default_attr:
            if key in allowed_attr:
                self.__dict__[key] = default_attr.get(key)

        # story media type means story-image & story-video
        if 'story' in self.media_types:
            self.media_types.remove('story')
            if 'story-image' not in self.media_types:
                self.media_types.append('story-image')
            if 'story-video' not in self.media_types:
                self.media_types.append('story-video')

        # Read latest_stamps file with ConfigParser
        self.latest_stamps_parser = None
        if self.latest_stamps:
            parser = configparser.ConfigParser()
            parser.read(self.latest_stamps)
            self.latest_stamps_parser = parser
            # If we have a latest_stamps file, latest must be true as it's the common flag
            self.latest = True

        # Set up a logger
        if self.logger is None:
            self.logger = Reporter.get_logger(level=logging.DEBUG, dest=default_attr.get('log_destination'), verbose=default_attr.get('verbose'))

        self.posts = []

        self.session = requests.Session()
        if self.no_check_certificate:
            self.session.verify = False

        try:
            if self.proxies and type(self.proxies) == str:
                self.session.proxies = json.loads(self.proxies)
        except ValueError:
            self.logger.error("Check is valid json type.")
            raise

        self.session.headers = {'user-agent': CHROME_WIN_UA}
        if self.cookiejar and os.path.exists(self.cookiejar):
            with open(self.cookiejar, 'rb') as f:
                self.session.cookies.update(pickle.load(f))
        self.session.cookies.set('ig_pr', '1')
        self.rhx_gis = ""

        self.cookies = None
        self.authenticated = False
        self.logged_in = False
        self.last_scraped_filemtime = 0
        if default_attr['filter']:
            self.filter = list(self.filter)

        self.quit = False

    def login(self):
        """Logs in to instagram."""
        self.session.headers.update({'Referer': self.base_url, 'user-agent': self.STORIES_UA})
        req = self.session.get(self.base_url)

        self.session.headers.update({'X-CSRFToken': req.cookies['csrftoken']})
        login_data = {'username': self.login_user, 'password': self.login_pass}
        login = self.session.post(self.login_url, data=login_data, allow_redirects=True)
        self.session.headers.update({'X-CSRFToken': login.cookies['csrftoken']})
        self.cookies = login.cookies
        login_text = json.loads(login.text)

        if login_text.get('authenticated') and login.status_code == 200:
            self.authenticated = True
            self.logged_in = True
            self.session.headers.update({'user-agent': CHROME_WIN_UA})
            self.rhx_gis = ""
        else:
            self.logger.error('Login failed for ' + self.login_user)

            if 'checkpoint_url' in login_text:
                checkpoint_url = login_text.get('checkpoint_url')
                self.logger.error('Please verify your account at ' + self.base_url[0:-1] + checkpoint_url)

                if self.interactive is True:
                    self.login_challenge(checkpoint_url)
            elif 'errors' in login_text:
                for count, error in enumerate(login_text['errors'].get('error')):
                    count += 1
                    self.logger.debug('Session error %(count)s: "%(error)s"' % locals())
            else:
                self.logger.error(json.dumps(login_text))

    def login_challenge(self, checkpoint_url):
        self.session.headers.update({'Referer': self.base_url})
        req = self.session.get(self.base_url[:-1] + checkpoint_url)
        self.session.headers.update({'X-CSRFToken': req.cookies['csrftoken'], 'X-Instagram-AJAX': '1'})

        self.session.headers.update({'Referer': self.base_url[:-1] + checkpoint_url})
        mode = int(input('Choose a challenge mode (0 - SMS, 1 - Email): '))
        challenge_data = {'choice': mode}
        challenge = self.session.post(self.base_url[:-1] + checkpoint_url, data=challenge_data, allow_redirects=True)
        self.session.headers.update({'X-CSRFToken': challenge.cookies['csrftoken'], 'X-Instagram-AJAX': '1'})

        code = int(input('Enter code received: '))
        code_data = {'security_code': code}
        code = self.session.post(self.base_url[:-1] + checkpoint_url, data=code_data, allow_redirects=True)
        self.session.headers.update({'X-CSRFToken': code.cookies['csrftoken']})
        self.cookies = code.cookies
        code_text = json.loads(code.text)

        if code_text.get('status') == 'ok':
            self.authenticated = True
            self.logged_in = True
        elif 'errors' in code.text:
            for count, error in enumerate(code_text['challenge']['errors']):
                count += 1
                self.logger.error('Session error %(count)s: "%(error)s"' % locals())
        else:
            self.logger.error(json.dumps(code_text))

    def logout(self):
        """Logs out of instagram."""
        if self.logged_in:
            try:
                logout_data = {'csrfmiddlewaretoken': self.cookies['csrftoken']}
                self.session.post(self.logout_url, data=logout_data)
                self.authenticated = False
                self.logged_in = False
            except requests.exceptions.RequestException:
                self.logger.warning('Failed to log out ' + self.login_user)
    
    def get_user_id(self, username):
        r = self.session.get(self.base_url + username + '/?__a=1')
        r_json = json.loads(r.text)
        if 'profilePage_' in r_json:
            return r_json['profilePage_']
        else:
            return 'User Not Found'
    
    def report_username(self, username_to_report, report_type):
        user_id = self.get_user_id(username_to_report)
        # report_return =
        self.report_userid(user_id, report_type)

    def report_userid(self, user_id, report_type):
        report_url = self.report_user_url.format(user_id, report_type)

        r = self.session.post(report_url)
        print(r.text)
        # r_json = json.loads(r.text)

    @staticmethod
    def get_logger(level=logging.DEBUG, dest='', verbose=0):
        """Returns a logger."""
        logger = logging.getLogger(__name__)

        dest +=  '/' if (dest !=  '') and dest[-1] != '/' else ''
        fh = logging.FileHandler(dest + 'instagram-scraper.log', 'w')
        fh.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
        fh.setLevel(level)
        logger.addHandler(fh)

        sh = logging.StreamHandler(sys.stdout)
        sh.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
        sh_lvls = [logging.ERROR, logging.WARNING, logging.INFO]
        sh.setLevel(sh_lvls[verbose])
        logger.addHandler(sh)

        logger.setLevel(level)

        return logger